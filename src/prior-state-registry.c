/* Copyright (C) 2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \brief State_Machine_Registry adapter implementation. Thin read-only
 *        wrapper over existing app-layer parser and detection-buffer
 *        registries; see prior-state-registry.h for contract.
 */

#include "suricata-common.h"
#include "prior-state-registry.h"

#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-detect-proto.h"

#include "detect.h"
#include "detect-engine.h"

#include "flow.h"

#include "util-debug.h"

/* STREAM_TOSERVER / STREAM_TOCLIENT are defined in the cbindgen'd rust
 * bindings header pulled in via rust.h, matching the rest of the tree. */
#include "rust.h"

/* -------------------------------------------------------------------------
 * Built-in hook names
 * -------------------------------------------------------------------------
 *
 * Every app-layer protocol exposes these four names regardless of whether
 * it registered its own named states. They map to completion-status values:
 *   request_started    -> progress 0 on TOSERVER
 *   request_complete   -> ts_complete on TOSERVER
 *   response_started   -> progress 0 on TOCLIENT
 *   response_complete  -> tc_complete on TOCLIENT
 */
#define HOOK_REQUEST_STARTED   "request_started"
#define HOOK_REQUEST_COMPLETE  "request_complete"
#define HOOK_RESPONSE_STARTED  "response_started"
#define HOOK_RESPONSE_COMPLETE "response_complete"

static bool IsBuiltInHookName(const char *name)
{
    return (strcmp(name, HOOK_REQUEST_STARTED) == 0 ||
            strcmp(name, HOOK_REQUEST_COMPLETE) == 0 ||
            strcmp(name, HOOK_RESPONSE_STARTED) == 0 ||
            strcmp(name, HOOK_RESPONSE_COMPLETE) == 0);
}

/* -------------------------------------------------------------------------
 * Representative ipproto per alproto
 * -------------------------------------------------------------------------
 *
 * The per-protocol state-funcs in the app-layer parser are keyed by
 * (alproto, FlowGetProtoMapping(ipproto)). To call AppLayerParserGetStateId
 * ByName / ...GetStateNameById we need a concrete ipproto. We ask
 * AppLayerProtoDetectSupportedIpprotos for the bitmap of ipprotos that
 * support the alproto and pick a preferred one (TCP, then UDP, then SCTP,
 * then any other set bit). This matches the design's notion of the
 * "representative ipproto for the protocol".
 */
static uint8_t RepresentativeIpproto(AppProto alproto)
{
    uint8_t ipprotos[256 / 8];
    memset(ipprotos, 0, sizeof(ipprotos));
    AppLayerProtoDetectSupportedIpprotos(alproto, ipprotos);

    /* Preferred order: TCP, UDP, SCTP. */
    const uint8_t preferred[] = { IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP };
    for (size_t i = 0; i < sizeof(preferred); i++) {
        const uint8_t p = preferred[i];
        if (ipprotos[p / 8] & (1u << (p % 8))) {
            return p;
        }
    }
    /* Fall back to the first ipproto set in the bitmap. */
    for (int p = 0; p < 256; p++) {
        if (ipprotos[p / 8] & (1u << (p % 8))) {
            return (uint8_t)p;
        }
    }
    /* Nothing registered for proto detection. Many protocols are still
     * parser-registered on a known ipproto even when they have no proto
     * detector; the parser tables are keyed by alproto alone for
     * completion status, so returning IPPROTO_TCP as a fallback is safe
     * for lookups that go through FlowGetProtoMapping (TCP maps to
     * FLOW_PROTO_TCP). */
    return IPPROTO_TCP;
}

/* -------------------------------------------------------------------------
 * Transport-handshake templates
 * ------------------------------------------------------------------------- */

static const TransportHandshakeRule g_tcp_handshake_rules[] = {
    {
        .label = "syn",
        .direction = TH_DIR_CLIENT_TO_SERVER,
        .condition_tail = "flow:to_server,not_established; flags:S,12;",
    },
    {
        .label = "syn-ack",
        .direction = TH_DIR_SERVER_TO_CLIENT,
        .condition_tail = "flow:to_client,not_established; flags:SA,12;",
    },
    {
        .label = "ack",
        .direction = TH_DIR_CLIENT_TO_SERVER,
        .condition_tail = "flow:to_server,not_established; flags:A,12;",
    },
    {
        .label = "post-handshake-passthrough",
        .direction = TH_DIR_BIDIR,
        .condition_tail = "flow:established;",
    },
};

static const TransportHandshakeRule g_udp_handshake_rules[] = {
    {
        .label = "udp-to-server",
        .direction = TH_DIR_CLIENT_TO_SERVER,
        .condition_tail = "",
    },
    {
        .label = "udp-to-client",
        .direction = TH_DIR_SERVER_TO_CLIENT,
        .condition_tail = "",
    },
};

/** The single in-tree transport-handshake table. Adding a transport is a
 *  matter of appending an entry here and registering its hook-proto name;
 *  no changes to the expander / validator are required. SCTP is a
 *  placeholder (count==0) today: GetTransportHandshakeTemplate returns \<0
 *  for it so the expander's Step 2 falls through naturally (Req 1.4),
 *  matching the design's "registered but empty" semantics. */
static const TransportHandshakeTemplate g_transport_handshake_templates[] = {
    {
        .ipproto = IPPROTO_TCP,
        .hook_proto = "tcp",
        .rules = g_tcp_handshake_rules,
        .count = (int)(sizeof(g_tcp_handshake_rules) /
                       sizeof(g_tcp_handshake_rules[0])),
    },
    {
        .ipproto = IPPROTO_UDP,
        .hook_proto = "udp",
        .rules = g_udp_handshake_rules,
        .count = (int)(sizeof(g_udp_handshake_rules) /
                       sizeof(g_udp_handshake_rules[0])),
    },
    {
        /* Placeholder: SCTP firewall support has not yet landed upstream.
         * count==0 causes GetTransportHandshakeTemplate() to return \<0
         * so the expander skips Step 2 for SCTP-carried app-layer flows
         * (they fall through to the app-layer prerequisite rules only). */
        .ipproto = IPPROTO_SCTP,
        .hook_proto = "sctp",
        .rules = NULL,
        .count = 0,
    },
};

static const size_t g_transport_handshake_template_count =
        sizeof(g_transport_handshake_templates) /
        sizeof(g_transport_handshake_templates[0]);

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

bool StateMachineRegistryHasProtocol(AppProto a)
{
    if (!AppProtoIsValid(a)) {
        return false;
    }
    /* A protocol is "present in the state-machine registry" if the app-
     * layer parser has registered a completion status for at least one
     * direction. The completion values are stored under FLOW_PROTO_DEFAULT
     * in the parser ctx table; an unregistered alproto reads 0/0, so
     * "has state machine" equivalent is: at least one direction has a
     * non-zero completion progress AND the parser has been enabled on
     * some ipproto (i.e., StateGetProgress is set somewhere). */
    const int ts = AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOSERVER);
    const int tc = AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOCLIENT);
    if (ts <= 0 && tc <= 0) {
        return false;
    }
    if (!AppLayerParserIsEnabled(a)) {
        return false;
    }
    return true;
}

int StateMachineRegistryGetInfo(AppProto a, StateMachineInfo *info)
{
    if (info == NULL) {
        return -1;
    }
    if (!StateMachineRegistryHasProtocol(a)) {
        return -1;
    }
    const uint8_t ipproto = RepresentativeIpproto(a);
    const int ts_complete =
            AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOSERVER);
    const int tc_complete =
            AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOCLIENT);

    /* "Has named states" means the parser registered GetStateIdByName
     * for this alproto on its representative ipproto. The cheapest probe
     * is to look up any state name we know is not built-in; state id 0
     * is always a valid progress value so GetStateNameById(0) returning
     * non-NULL implies GetStateNameById is registered, which in turn
     * implies GetStateIdByName is registered (they are registered as a
     * pair, see AppLayerParserRegisterGetStateFuncs). */
    const char *probe =
            AppLayerParserGetStateNameById(ipproto, a, 0, STREAM_TOSERVER);
    const bool has_named = (probe != NULL);

    info->alproto = a;
    info->ts_complete = ts_complete;
    info->tc_complete = tc_complete;
    info->has_named_states = has_named;
    return 0;
}

/** \internal
 *  \brief Fill \p out with the built-in hook matching \p hook_name, using
 *         completion-status values on the representative ipproto.
 *  \retval 0 on match, \<0 if \p hook_name is not a built-in name. */
static int ResolveBuiltInHook(AppProto a, uint8_t ipproto, const char *hook_name,
        StateMachineState *out)
{
    const int ts_complete =
            AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOSERVER);
    const int tc_complete =
            AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOCLIENT);
    (void)ipproto; /* reserved for future use; built-in names are direction-pure */

    if (strcmp(hook_name, HOOK_REQUEST_STARTED) == 0) {
        out->progress = 0;
        out->direction = STREAM_TOSERVER;
        out->name = HOOK_REQUEST_STARTED;
        out->is_builtin = true;
        return 0;
    }
    if (strcmp(hook_name, HOOK_REQUEST_COMPLETE) == 0) {
        out->progress = ts_complete;
        out->direction = STREAM_TOSERVER;
        out->name = HOOK_REQUEST_COMPLETE;
        out->is_builtin = true;
        return 0;
    }
    if (strcmp(hook_name, HOOK_RESPONSE_STARTED) == 0) {
        out->progress = 0;
        out->direction = STREAM_TOCLIENT;
        out->name = HOOK_RESPONSE_STARTED;
        out->is_builtin = true;
        return 0;
    }
    if (strcmp(hook_name, HOOK_RESPONSE_COMPLETE) == 0) {
        out->progress = tc_complete;
        out->direction = STREAM_TOCLIENT;
        out->name = HOOK_RESPONSE_COMPLETE;
        out->is_builtin = true;
        return 0;
    }
    return -1;
}

int StateMachineRegistryResolve(AppProto a, const char *hook_name,
        StateMachineState *out, char *errbuf, size_t errbuflen)
{
    if (out == NULL || hook_name == NULL) {
        return -1;
    }

    if (!StateMachineRegistryHasProtocol(a)) {
        if (errbuf && errbuflen) {
            snprintf(errbuf, errbuflen,
                    "protocol '%s' is not registered in the state-machine registry",
                    AppProtoToString(a));
        }
        return -1;
    }

    const uint8_t ipproto = RepresentativeIpproto(a);

    /* Built-in hooks short-circuit the named-state table. */
    if (IsBuiltInHookName(hook_name)) {
        return ResolveBuiltInHook(a, ipproto, hook_name, out);
    }

    /* Named-state lookup on both directions. Ambiguity (same name in both
     * directions) is an unambiguous error per design §Components.3. */
    const int progress_ts =
            AppLayerParserGetStateIdByName(ipproto, a, hook_name, STREAM_TOSERVER);
    const int progress_tc =
            AppLayerParserGetStateIdByName(ipproto, a, hook_name, STREAM_TOCLIENT);

    if (progress_ts >= 0 && progress_tc >= 0) {
        if (errbuf && errbuflen) {
            snprintf(errbuf, errbuflen,
                    "hook '%s' is ambiguous on protocol '%s': present in both "
                    "TOSERVER (progress %d) and TOCLIENT (progress %d) tables",
                    hook_name, AppProtoToString(a), progress_ts, progress_tc);
        }
        return -1;
    }
    if (progress_ts >= 0) {
        out->progress = progress_ts;
        out->direction = STREAM_TOSERVER;
        out->name = AppLayerParserGetStateNameById(ipproto, a, progress_ts,
                STREAM_TOSERVER);
        if (out->name == NULL) {
            out->name = hook_name;
        }
        out->is_builtin = false;
        return 0;
    }
    if (progress_tc >= 0) {
        out->progress = progress_tc;
        out->direction = STREAM_TOCLIENT;
        out->name = AppLayerParserGetStateNameById(ipproto, a, progress_tc,
                STREAM_TOCLIENT);
        if (out->name == NULL) {
            out->name = hook_name;
        }
        out->is_builtin = false;
        return 0;
    }

    if (errbuf && errbuflen) {
        snprintf(errbuf, errbuflen,
                "protocol '%s' has no state named '%s'",
                AppProtoToString(a), hook_name);
    }
    return -1;
}

int StateMachineRegistryPrerequisites(AppProto a, uint8_t direction,
        int decision, StateMachineState *out, int max)
{
    if (out == NULL || max <= 0) {
        return -1;
    }
    if (direction != STREAM_TOSERVER && direction != STREAM_TOCLIENT) {
        return -1;
    }
    if (!StateMachineRegistryHasProtocol(a)) {
        return -1;
    }

    const uint8_t ipproto = RepresentativeIpproto(a);
    const int complete =
            AppLayerParserGetStateProgressCompletionStatus(a, direction);
    const char *probe0 =
            AppLayerParserGetStateNameById(ipproto, a, 0, direction);
    const bool has_named = (probe0 != NULL);

    int count = 0;

    /* Protocols without named states (DNS, NTP, SNMP) expose only the two
     * built-in hooks per direction: request_started (progress 0) and
     * request_complete (progress ts_complete), or the response equivalents
     * on TOCLIENT. For a decision hook that is itself a built-in,
     * prerequisites collapse to the "_started" hook when decision>0. */
    if (!has_named) {
        if (direction == STREAM_TOSERVER) {
            if (decision > 0 && count < max) {
                out[count].progress = 0;
                out[count].direction = STREAM_TOSERVER;
                out[count].name = HOOK_REQUEST_STARTED;
                out[count].is_builtin = true;
                count++;
            }
            if (decision > complete && count < max) {
                /* decision hook lies past request_complete: request_complete
                 * becomes a prerequisite too. In practice validate should
                 * reject this case, but the enumeration stays consistent. */
                out[count].progress = complete;
                out[count].direction = STREAM_TOSERVER;
                out[count].name = HOOK_REQUEST_COMPLETE;
                out[count].is_builtin = true;
                count++;
            }
        } else {
            if (decision > 0 && count < max) {
                out[count].progress = 0;
                out[count].direction = STREAM_TOCLIENT;
                out[count].name = HOOK_RESPONSE_STARTED;
                out[count].is_builtin = true;
                count++;
            }
            if (decision > complete && count < max) {
                out[count].progress = complete;
                out[count].direction = STREAM_TOCLIENT;
                out[count].name = HOOK_RESPONSE_COMPLETE;
                out[count].is_builtin = true;
                count++;
            }
        }
        return count;
    }

    /* Named-state path: enumerate every progress p in [0, decision) and
     * record the state's name for that direction. Skip holes (progress
     * values that have no registered name on this direction — some
     * protocols leave gaps). The output is already ascending because the
     * loop runs in ascending order. */
    for (int p = 0; p < decision && count < max; p++) {
        const char *name = AppLayerParserGetStateNameById(ipproto, a, p, direction);
        if (name == NULL) {
            continue;
        }
        out[count].progress = p;
        out[count].direction = direction;
        out[count].name = name;
        out[count].is_builtin = IsBuiltInHookName(name);
        count++;
    }
    return count;
}

int StateMachineRegistryKeywordRequires(
        const char *keyword, AppProto *a, uint8_t *direction, int *progress)
{
    if (keyword == NULL || a == NULL || direction == NULL || progress == NULL) {
        return -1;
    }

    /* The global DetectEngineAppInspectionEngine list is not directly
     * exposed, but the per-ctx copy is — and it contains the same
     * (alproto, dir, progress, sm_list) tuples the global list carries.
     * We take a reference to the current ctx, walk its buffer-name -> id
     * hash to look up the keyword's buffer id, then walk app_inspect_
     * engines for a matching entry. If no ctx is active yet (very early
     * startup, before DetectEngineCtxInit has run), there is nothing we
     * can look up against — return \<0. */
    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();
    if (de_ctx == NULL) {
        return -1;
    }

    int rc = -1;

    const int buf_id = DetectBufferTypeGetByName(keyword);
    if (buf_id < 0) {
        goto out;
    }

    for (const DetectEngineAppInspectionEngine *t = de_ctx->app_inspect_engines;
            t != NULL; t = t->next) {
        if (t->sm_list == buf_id) {
            *a = t->alproto;
            /* DetectEngineAppInspectionEngine.dir uses 0 for TOSERVER and
             * 1 for TOCLIENT (see AppLayerInspectEngineRegisterInternal
             * in detect-engine.c). Translate back to STREAM_TO* flags. */
            *direction = (t->dir == 0) ? STREAM_TOSERVER : STREAM_TOCLIENT;
            *progress = t->progress;
            rc = 0;
            break;
        }
    }

out:
    DetectEngineDeReference(&de_ctx);
    return rc;
}

int StateMachineRegistryGetSupportedTransports(AppProto a, uint8_t *out, int max)
{
    if (out == NULL || max <= 0) {
        return -1;
    }
    if (!AppProtoIsValid(a)) {
        return -1;
    }

    uint8_t ipprotos_bitmap[256 / 8];
    memset(ipprotos_bitmap, 0, sizeof(ipprotos_bitmap));
    AppLayerProtoDetectSupportedIpprotos(a, ipprotos_bitmap);

    int count = 0;

    /* Emit the preferred ipprotos first in stable order: TCP, UDP, SCTP.
     * This keeps the expander's Step 2 output deterministic across
     * releases — DNS will always emit its TCP handshake block before its
     * UDP block, for instance. */
    const uint8_t preferred[] = { IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP };
    for (size_t i = 0; i < sizeof(preferred); i++) {
        const uint8_t p = preferred[i];
        if (ipprotos_bitmap[p / 8] & (1u << (p % 8))) {
            if (count >= max) {
                return count;
            }
            out[count++] = p;
            /* Clear the bit so the fall-through loop below doesn't re-emit. */
            ipprotos_bitmap[p / 8] &= (uint8_t)~(1u << (p % 8));
        }
    }

    /* Then emit every remaining ipproto in ascending numeric order. */
    for (int p = 0; p < 256 && count < max; p++) {
        if (ipprotos_bitmap[p / 8] & (1u << (p % 8))) {
            out[count++] = (uint8_t)p;
        }
    }

    if (count == 0) {
        /* No ipproto registered for this alproto — treat as unregistered. */
        return -1;
    }
    return count;
}

int StateMachineRegistryGetTransportHandshakeTemplate(
        uint8_t ipproto, const TransportHandshakeTemplate **out)
{
    if (out == NULL) {
        return -1;
    }
    for (size_t i = 0; i < g_transport_handshake_template_count; i++) {
        const TransportHandshakeTemplate *t = &g_transport_handshake_templates[i];
        if (t->ipproto == ipproto) {
            /* A registered-but-empty template (placeholder, e.g. SCTP)
             * behaves as "no template" so Step 2 of the expansion
             * algorithm falls through (Req 1.4). */
            if (t->count <= 0 || t->rules == NULL) {
                return -1;
            }
            *out = t;
            return 0;
        }
    }
    return -1;
}

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
 * \brief Prior_State expander implementation. See prior-state-expand.h
 *        for the contract and the POC vs Phase-2 scope boundary.
 *
 * Customer-facing SID abstraction (design Decision 2, Req 7.3). Every
 * auto-accepted Expanded_Rule this module emits — both the Step 2
 * transport-handshake rules (EmitTransportHandshakeRules) and the
 * Step 3 app-layer prerequisite rules (EmitAppLayerPrerequisitesForDirection)
 * — carries `noalert;` in its options block. That keeps the expansion
 * invisible on customer-facing alert surfaces even if a future engine
 * change gives `accept:*` rules a default alert policy: the firewall
 * tables still gate the packet, but `PacketAlertFinalize` never enqueues
 * a record under a derived Sub_SID. The Decision_Hook rule emitted in
 * Step 4 (EmitDecisionHookRule) deliberately does NOT carry `noalert;`
 * — it is the single rule carrying the author's Parent_SID and is the
 * only place customer-facing output is allowed to originate from the
 * expansion.
 */

#include "suricata-common.h"
#include "prior-state-expand.h"

#include "action-globals.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "prior-state-registry.h"

#include "util-debug.h"
#include "util-mem.h"

#include "rust.h" /* STREAM_TOSERVER / STREAM_TOCLIENT */

/* Upper bound on the number of prerequisite states per direction that the
 * expander will enumerate. 64 is comfortably above any protocol the
 * app-layer parser registers today (HTTP/1 tops out at ~12 states across
 * both directions) and keeps the enumeration on the stack. */
#define PRIOR_STATE_EXPAND_MAX_PREREQS 64

/* Upper bound on a single rendered rule string. Conservative — the
 * longest rule the POC emits is the Decision_Hook rule where the
 * author's options_remainder plus msg/rev/gid/sid tail can be ~1 KiB. */
#define PRIOR_STATE_EXPAND_RULE_BUF_SZ 2048

/* -------------------------------------------------------------------------
 * Error helpers
 * ------------------------------------------------------------------------- */

static void SetErr(char *errbuf, size_t errbuflen, const char *fmt, ...)
        __attribute__((format(printf, 3, 4)));

static void SetErr(char *errbuf, size_t errbuflen, const char *fmt, ...)
{
    if (errbuf == NULL || errbuflen == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(errbuf, errbuflen, fmt, ap);
    va_end(ap);
}

/* -------------------------------------------------------------------------
 * FNV-1a 32-bit hash for the Sub_SID formula
 * -------------------------------------------------------------------------
 *
 * FNV-1a is one of the hashes referenced in the design for the Sub_SID
 * computation. We implement it inline so the Prior_State module carries
 * no dependency on util-hash-string's (murmur-based) helpers, and so
 * the formula is independently auditable from the design document.
 */

#define FNV1A_32_OFFSET 0x811c9dc5u
#define FNV1A_32_PRIME  0x01000193u

static uint32_t Fnv1a32(const char *s)
{
    uint32_t h = FNV1A_32_OFFSET;
    if (s == NULL) {
        return h;
    }
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        h ^= (uint32_t)*p;
        h *= FNV1A_32_PRIME;
    }
    return h;
}

uint32_t PriorStateExpandSubRuntimeSid(
        const char *file, uint32_t parent_sid, uint16_t sub_index)
{
    const uint32_t mixed =
            Fnv1a32(file) ^ parent_sid ^ (uint32_t)sub_index;
    return 0x80000000u | (mixed & 0x7FFFFFFFu);
}

/* -------------------------------------------------------------------------
 * Scope rendering
 * ------------------------------------------------------------------------- */

/** \brief Map ACTION_SCOPE_* to the string token the firewall parser
 *         expects after "accept:" (e.g. "tx", "flow", "hook"). */
static const char *ScopeToStr(uint8_t scope)
{
    switch (scope) {
        case (uint8_t)ACTION_SCOPE_HOOK:
            return "hook";
        case (uint8_t)ACTION_SCOPE_FLOW:
            return "flow";
        case (uint8_t)ACTION_SCOPE_TX:
            return "tx";
        case (uint8_t)ACTION_SCOPE_PACKET:
            return "packet";
        default:
            return "auto";
    }
}

/* -------------------------------------------------------------------------
 * ExpandedRuleList scratch accumulator
 * -------------------------------------------------------------------------
 *
 * The expander builds the output list incrementally. `Accumulator` owns
 * the three parallel arrays + count + capacity and grows geometrically.
 * It never holds a reference to caller-owned memory — every string
 * stored is an owned heap allocation. On error the accumulator's
 * contents are released by AccumulatorFree.
 */

typedef struct Accumulator_ {
    char **strings;
    char **labels;
    uint16_t *sub_indexes;
    int count;
    int cap;
} Accumulator;

static void AccumulatorInit(Accumulator *a)
{
    memset(a, 0, sizeof(*a));
}

static void AccumulatorFree(Accumulator *a)
{
    if (a == NULL) {
        return;
    }
    for (int i = 0; i < a->count; i++) {
        SCFree(a->strings[i]);
        SCFree(a->labels[i]);
    }
    SCFree(a->strings);
    SCFree(a->labels);
    SCFree(a->sub_indexes);
    memset(a, 0, sizeof(*a));
}

static int AccumulatorReserve(Accumulator *a, int needed)
{
    if (needed <= a->cap) {
        return 0;
    }
    int new_cap = (a->cap == 0) ? 16 : a->cap * 2;
    while (new_cap < needed) {
        new_cap *= 2;
    }
    char **ns = SCRealloc(a->strings, (size_t)new_cap * sizeof(*ns));
    if (ns == NULL) {
        return -1;
    }
    a->strings = ns;
    char **nl = SCRealloc(a->labels, (size_t)new_cap * sizeof(*nl));
    if (nl == NULL) {
        return -1;
    }
    a->labels = nl;
    uint16_t *ni = SCRealloc(a->sub_indexes, (size_t)new_cap * sizeof(*ni));
    if (ni == NULL) {
        return -1;
    }
    a->sub_indexes = ni;
    a->cap = new_cap;
    return 0;
}

/** \brief Append a fully-rendered rule string and its attribution
 *         metadata to the accumulator. Takes ownership of \p rule_string
 *         and \p label on success; on failure both are freed here so the
 *         caller never has to untangle a partial success. */
static int AccumulatorPush(Accumulator *a, char *rule_string, char *label, uint16_t sub_index)
{
    if (AccumulatorReserve(a, a->count + 1) < 0) {
        SCFree(rule_string);
        SCFree(label);
        return -1;
    }
    a->strings[a->count] = rule_string;
    a->labels[a->count] = label;
    a->sub_indexes[a->count] = sub_index;
    a->count++;
    return 0;
}

/* -------------------------------------------------------------------------
 * Step 2 — transport handshake emission
 * ------------------------------------------------------------------------- */

/** \brief Render the five-tuple segment for a transport-handshake rule
 *         per the template's direction recipe. */
static int RenderFiveTuple(uint8_t direction, const PriorStateRule *r, char *buf, size_t bufsz)
{
    switch (direction) {
        case TH_DIR_CLIENT_TO_SERVER:
            return snprintf(buf, bufsz, "%s %s -> %s %s", r->src_addr, r->src_port, r->dst_addr,
                    r->dst_port);
        case TH_DIR_SERVER_TO_CLIENT:
            return snprintf(buf, bufsz, "%s %s -> %s %s", r->dst_addr, r->dst_port, r->src_addr,
                    r->src_port);
        case TH_DIR_BIDIR:
            return snprintf(buf, bufsz, "%s %s <> %s %s", r->src_addr, r->src_port, r->dst_addr,
                    r->dst_port);
        default:
            return -1;
    }
}

/** \brief Emit every rule in the transport-handshake template, starting
 *         at sub index *\p next_sub and advancing it past the last rule
 *         pushed. */
static int EmitTransportHandshakeRules(Accumulator *a, const PriorStateRule *r,
        const TransportHandshakeTemplate *tpl, uint16_t *next_sub, char *errbuf, size_t errbuflen)
{
    for (int i = 0; i < tpl->count; i++) {
        const TransportHandshakeRule *th = &tpl->rules[i];
        const uint16_t sub_index = (*next_sub)++;
        const uint32_t sub_sid =
                PriorStateExpandSubRuntimeSid(r->file, r->sid, sub_index);

        char five_tuple[256];
        if (RenderFiveTuple(th->direction, r, five_tuple, sizeof(five_tuple)) < 0) {
            SetErr(errbuf, errbuflen,
                    "unsupported transport-handshake direction code %u for '%s'",
                    (unsigned)th->direction, tpl->hook_proto);
            return PRIOR_STATE_EXPAND_REGISTRY;
        }

        /* Rule shape (TCP example, sub 1):
         *   accept:hook tcp:all <five-tuple> (flow:...; flags:...; noalert; sid:<SUB>;)
         *
         * UDP entries carry condition_tail == "" so the options block
         * collapses to `noalert; sid:<SUB>;`. Every auto-accepted rule
         * carries `noalert;` so expansion stays invisible on the
         * customer-facing alert surface (design §Decision 2). The
         * Decision_Hook rule emitted in Step 4 is *not* marked
         * noalert — that's the rule carrying the Parent_SID. */
        char *rule = SCMalloc(PRIOR_STATE_EXPAND_RULE_BUF_SZ);
        if (rule == NULL) {
            SetErr(errbuf, errbuflen, "out of memory rendering transport handshake rule");
            return PRIOR_STATE_EXPAND_OOM;
        }
        int n;
        if (th->condition_tail != NULL && th->condition_tail[0] != '\0') {
            n = snprintf(rule, PRIOR_STATE_EXPAND_RULE_BUF_SZ,
                    "accept:hook %s:all %s (%s noalert; sid:%" PRIu32 ";)", tpl->hook_proto,
                    five_tuple, th->condition_tail, sub_sid);
        } else {
            n = snprintf(rule, PRIOR_STATE_EXPAND_RULE_BUF_SZ,
                    "accept:hook %s:all %s (noalert; sid:%" PRIu32 ";)", tpl->hook_proto,
                    five_tuple, sub_sid);
        }
        if (n < 0 || (size_t)n >= PRIOR_STATE_EXPAND_RULE_BUF_SZ) {
            SCFree(rule);
            SetErr(errbuf, errbuflen, "transport-handshake rule rendering overflowed the buffer");
            return PRIOR_STATE_EXPAND_OOM;
        }

        char *label = SCStrdup(th->label != NULL ? th->label : "");
        if (label == NULL) {
            SCFree(rule);
            SetErr(errbuf, errbuflen, "out of memory duplicating handshake label");
            return PRIOR_STATE_EXPAND_OOM;
        }

        if (AccumulatorPush(a, rule, label, sub_index) < 0) {
            SetErr(errbuf, errbuflen, "out of memory appending transport handshake rule");
            return PRIOR_STATE_EXPAND_OOM;
        }
    }
    return PRIOR_STATE_EXPAND_OK;
}

/* -------------------------------------------------------------------------
 * Step 3 — app-layer prerequisite emission
 * ------------------------------------------------------------------------- */

/** \brief Emit the app-layer prerequisite rules for a single direction.
 *
 *  States are enumerated in ascending-progress order by the registry,
 *  and the rules are emitted in that same order. Ports collapse to
 *  `any → any` per design §Step 3; the five-tuple addresses stay as the
 *  author's tokens on the decision direction and swap on the opposite
 *  direction. */
static int EmitAppLayerPrerequisitesForDirection(Accumulator *a, const PriorStateRule *r,
        uint8_t direction, int bound, uint16_t *next_sub, char *errbuf, size_t errbuflen)
{
    StateMachineState prereqs[PRIOR_STATE_EXPAND_MAX_PREREQS];
    memset(prereqs, 0, sizeof(prereqs));

    const int n = StateMachineRegistryPrerequisites(r->alproto, direction, bound, prereqs,
            (int)(sizeof(prereqs) / sizeof(prereqs[0])));
    if (n < 0) {
        SetErr(errbuf, errbuflen,
                "registry refused prerequisite enumeration on '%s' direction %u",
                r->proto, (unsigned)direction);
        return PRIOR_STATE_EXPAND_REGISTRY;
    }

    const bool reversed = (direction != r->decision_direction);

    for (int i = 0; i < n; i++) {
        const StateMachineState *s = &prereqs[i];
        if (s->name == NULL) {
            continue;
        }

        const uint16_t sub_index = (*next_sub)++;
        const uint32_t sub_sid =
                PriorStateExpandSubRuntimeSid(r->file, r->sid, sub_index);

        char *rule = SCMalloc(PRIOR_STATE_EXPAND_RULE_BUF_SZ);
        if (rule == NULL) {
            SetErr(errbuf, errbuflen, "out of memory rendering prerequisite rule");
            return PRIOR_STATE_EXPAND_OOM;
        }

        int written;
        if (!reversed) {
            written = snprintf(rule, PRIOR_STATE_EXPAND_RULE_BUF_SZ,
                    "accept:hook %s:%s %s any -> %s any (noalert; sid:%" PRIu32 ";)", r->proto,
                    s->name, r->src_addr, r->dst_addr, sub_sid);
        } else {
            written = snprintf(rule, PRIOR_STATE_EXPAND_RULE_BUF_SZ,
                    "accept:hook %s:%s %s any -> %s any (noalert; sid:%" PRIu32 ";)", r->proto,
                    s->name, r->dst_addr, r->src_addr, sub_sid);
        }
        if (written < 0 || (size_t)written >= PRIOR_STATE_EXPAND_RULE_BUF_SZ) {
            SCFree(rule);
            SetErr(errbuf, errbuflen, "prerequisite rule rendering overflowed the buffer");
            return PRIOR_STATE_EXPAND_OOM;
        }

        char *label = SCStrdup(s->name);
        if (label == NULL) {
            SCFree(rule);
            SetErr(errbuf, errbuflen, "out of memory duplicating prerequisite label");
            return PRIOR_STATE_EXPAND_OOM;
        }

        if (AccumulatorPush(a, rule, label, sub_index) < 0) {
            SetErr(errbuf, errbuflen, "out of memory appending prerequisite rule");
            return PRIOR_STATE_EXPAND_OOM;
        }
    }
    return PRIOR_STATE_EXPAND_OK;
}

/* -------------------------------------------------------------------------
 * Step 4 — Decision_Hook emission
 * ------------------------------------------------------------------------- */

/** \brief Emit the Decision_Hook rule carrying the author's action, five-
 *         tuple, detection keywords, and SID. Assigned sub index 0. */
static int EmitDecisionHookRule(
        Accumulator *a, const PriorStateRule *r, char *errbuf, size_t errbuflen)
{
    const char *scope_str = ScopeToStr(r->action_scope);
    char *rule = SCMalloc(PRIOR_STATE_EXPAND_RULE_BUF_SZ);
    if (rule == NULL) {
        SetErr(errbuf, errbuflen, "out of memory rendering decision hook rule");
        return PRIOR_STATE_EXPAND_OOM;
    }

    /* Options block:
     *   [msg:"...";] [options_remainder] sid:<parent>; rev:<rev>; [gid:<gid>;]
     *
     * `options_remainder` from the parser is already a sequence of
     * "keyword[:value]; " chunks with no leading space and a trailing
     * ';' (the parser trims the final space). We splice it in and then
     * append `sid:`, `rev:`, and optionally `gid:`. The Decision_Hook
     * entry keeps the author's SID — only auto-accepted rules get the
     * derived sub-runtime SID. */
    char options[PRIOR_STATE_EXPAND_RULE_BUF_SZ];
    options[0] = '\0';
    size_t off = 0;
    int w;

    if (r->msg != NULL && r->msg[0] != '\0') {
        w = snprintf(options + off, sizeof(options) - off, "msg:\"%s\"; ", r->msg);
        if (w < 0 || (size_t)w >= sizeof(options) - off) {
            SCFree(rule);
            SetErr(errbuf, errbuflen, "decision hook msg rendering overflowed the buffer");
            return PRIOR_STATE_EXPAND_OOM;
        }
        off += (size_t)w;
    }

    if (r->options_remainder != NULL && r->options_remainder[0] != '\0') {
        w = snprintf(options + off, sizeof(options) - off, "%s ", r->options_remainder);
        if (w < 0 || (size_t)w >= sizeof(options) - off) {
            SCFree(rule);
            SetErr(errbuf, errbuflen, "decision hook options_remainder rendering overflowed");
            return PRIOR_STATE_EXPAND_OOM;
        }
        off += (size_t)w;
    }

    w = snprintf(options + off, sizeof(options) - off, "sid:%" PRIu32 ";", r->sid);
    if (w < 0 || (size_t)w >= sizeof(options) - off) {
        SCFree(rule);
        SetErr(errbuf, errbuflen, "decision hook sid rendering overflowed the buffer");
        return PRIOR_STATE_EXPAND_OOM;
    }
    off += (size_t)w;

    if (r->rev != 0 && r->rev != 1) {
        w = snprintf(options + off, sizeof(options) - off, " rev:%" PRIu32 ";", r->rev);
        if (w < 0 || (size_t)w >= sizeof(options) - off) {
            SCFree(rule);
            SetErr(errbuf, errbuflen, "decision hook rev rendering overflowed the buffer");
            return PRIOR_STATE_EXPAND_OOM;
        }
        off += (size_t)w;
    }
    if (r->gid != 0 && r->gid != 1) {
        w = snprintf(options + off, sizeof(options) - off, " gid:%" PRIu32 ";", r->gid);
        if (w < 0 || (size_t)w >= sizeof(options) - off) {
            SCFree(rule);
            SetErr(errbuf, errbuflen, "decision hook gid rendering overflowed the buffer");
            return PRIOR_STATE_EXPAND_OOM;
        }
        off += (size_t)w;
    }

    const int total = snprintf(rule, PRIOR_STATE_EXPAND_RULE_BUF_SZ,
            "accept:%s %s:%s %s %s %s %s %s (%s)", scope_str, r->proto, r->state, r->src_addr,
            r->src_port, r->direction_op, r->dst_addr, r->dst_port, options);
    if (total < 0 || (size_t)total >= PRIOR_STATE_EXPAND_RULE_BUF_SZ) {
        SCFree(rule);
        SetErr(errbuf, errbuflen, "decision hook rule rendering overflowed the buffer");
        return PRIOR_STATE_EXPAND_OOM;
    }

    char *label = SCStrdup("");
    if (label == NULL) {
        SCFree(rule);
        SetErr(errbuf, errbuflen, "out of memory duplicating decision hook label");
        return PRIOR_STATE_EXPAND_OOM;
    }

    if (AccumulatorPush(a, rule, label, 0) < 0) {
        SetErr(errbuf, errbuflen, "out of memory appending decision hook rule");
        return PRIOR_STATE_EXPAND_OOM;
    }
    return PRIOR_STATE_EXPAND_OK;
}

/* -------------------------------------------------------------------------
 * Public entry point
 * ------------------------------------------------------------------------- */

void ExpandedRuleListFree(ExpandedRuleList *l)
{
    if (l == NULL) {
        return;
    }
    for (int i = 0; i < l->count; i++) {
        SCFree(l->strings[i]);
        SCFree(l->labels[i]);
    }
    SCFree(l->strings);
    SCFree(l->labels);
    SCFree(l->sub_indexes);
    SCFree(l);
}

int PriorStateExpand(
        const PriorStateRule *r, ExpandedRuleList **out, char *errbuf, size_t errbuflen)
{
    if (r == NULL || out == NULL) {
        SetErr(errbuf, errbuflen, "NULL input to PriorStateExpand");
        return PRIOR_STATE_EXPAND_ERR_NULL_INPUT;
    }
    *out = NULL;

    /* POC scope: only :tx is expanded. :hook and :flow land in task 13. */
    if (r->action_scope != (uint8_t)ACTION_SCOPE_TX) {
        SetErr(errbuf, errbuflen,
                "only 'accept:tx' is supported in the POC; scope '%s' will be lifted in Phase 2",
                ScopeToStr(r->action_scope));
        return PRIOR_STATE_EXPAND_SCOPE_UNSUPPORTED;
    }

    /* Step 0 — direction set for :tx is { TOSERVER, TOCLIENT }. */

    /* Step 1 — determine the opposite-direction completion bound. */
    const uint8_t decision_dir = r->decision_direction;
    const uint8_t opposite_dir =
            (decision_dir == STREAM_TOSERVER) ? STREAM_TOCLIENT : STREAM_TOSERVER;

    StateMachineInfo info;
    memset(&info, 0, sizeof(info));
    if (StateMachineRegistryGetInfo(r->alproto, &info) < 0) {
        SetErr(errbuf, errbuflen, "state-machine registry has no info for protocol '%s'",
                r->proto);
        return PRIOR_STATE_EXPAND_REGISTRY;
    }
    const int opposite_complete =
            (opposite_dir == STREAM_TOSERVER) ? info.ts_complete : info.tc_complete;
    /* The registry's "up to completion" semantics mean we emit every
     * state with progress < complete+1, i.e., up to and including the
     * completion state. StateMachineRegistryPrerequisites' bound is
     * exclusive, so we pass complete+1. For the decision direction we
     * pass decision_progress itself (prerequisites strictly before the
     * decision — the decision hook itself is emitted by Step 4). */
    const int opposite_bound = opposite_complete + 1;
    const int decision_bound = r->decision_progress;

    Accumulator acc;
    AccumulatorInit(&acc);

    uint16_t next_sub = 1;

    /* Step 2 — iterate every transport the registry advertises for this
     * alproto (TLS → {TCP}; DNS → {TCP, UDP}; SNMP → {UDP}). Sub-SID
     * numbering is contiguous across transports so DNS emits sub indices
     * 1..4 (TCP handshake) then 5..6 (UDP transport) before Step 3 picks
     * up at sub 7 for the app-layer prerequisites. */
    for (int i = 0; i < r->transport_ipprotos_count; i++) {
        const TransportHandshakeTemplate *tpl = NULL;
        if (StateMachineRegistryGetTransportHandshakeTemplate(
                    r->transport_ipprotos[i], &tpl) == 0 &&
                tpl != NULL && tpl->count > 0) {
            int rc = EmitTransportHandshakeRules(&acc, r, tpl, &next_sub, errbuf, errbuflen);
            if (rc != PRIOR_STATE_EXPAND_OK) {
                AccumulatorFree(&acc);
                return rc;
            }
        }
        /* SCTP / non-templated ipproto: fall through, emit nothing (Req 1.4). */
    }

    /* Step 3 — app-layer prerequisite rules. Decision direction first
     * (ascending progress), then opposite direction (ascending progress).
     * This matches the sub-index numbering in the TLS SNI worked
     * example: sub 5 is `tls:client_in_progress` (TOSERVER), subs 6-11
     * are the TOCLIENT states in ascending order. */
    int rc = EmitAppLayerPrerequisitesForDirection(
            &acc, r, decision_dir, decision_bound, &next_sub, errbuf, errbuflen);
    if (rc != PRIOR_STATE_EXPAND_OK) {
        AccumulatorFree(&acc);
        return rc;
    }
    rc = EmitAppLayerPrerequisitesForDirection(
            &acc, r, opposite_dir, opposite_bound, &next_sub, errbuf, errbuflen);
    if (rc != PRIOR_STATE_EXPAND_OK) {
        AccumulatorFree(&acc);
        return rc;
    }

    /* Step 4 — Decision_Hook rule. */
    rc = EmitDecisionHookRule(&acc, r, errbuf, errbuflen);
    if (rc != PRIOR_STATE_EXPAND_OK) {
        AccumulatorFree(&acc);
        return rc;
    }

    /* Step 5 — Sub_SID numbering is already handled inline: prerequisite
     * rules were pushed with sub indices 1..N-1 in emission order; the
     * Decision_Hook rule carries sub index 0. The runtime SID formula is
     * applied by PriorStateExpandSubRuntimeSid at render time. No
     * provenance-table write in Phase 1 — the deterministic formula is
     * the sole source of truth until task 14 introduces the table. */

    ExpandedRuleList *list = SCCalloc(1, sizeof(*list));
    if (list == NULL) {
        AccumulatorFree(&acc);
        SetErr(errbuf, errbuflen, "out of memory allocating ExpandedRuleList");
        return PRIOR_STATE_EXPAND_OOM;
    }
    list->strings = acc.strings;
    list->labels = acc.labels;
    list->sub_indexes = acc.sub_indexes;
    list->count = acc.count;
    list->parent_sid = r->sid;
    /* Ownership transferred; wipe the accumulator so AccumulatorFree
     * would be a no-op. */
    memset(&acc, 0, sizeof(acc));

    *out = list;
    return PRIOR_STATE_EXPAND_OK;
}

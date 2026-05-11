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
 * \brief State_Machine_Registry adapter for the firewall "accept-prior-states"
 *        feature. This is a read-only view over existing Suricata app-layer
 *        parser registrations (AppLayerParser*) and the detection buffer /
 *        app-layer inspect-engine registry. It centralises every protocol
 *        state-machine query the Prior_State expander and validator need so
 *        the feature is registry-driven across every registered alproto.
 *
 * See design §Components.3 for the contract. Neighbouring Suricata headers
 * use the SURICATA_*_H include-guard style, so that is what we follow here;
 * this file is the "prior-state-registry.h" referenced by the design.
 */

#ifndef SURICATA_PRIOR_STATE_REGISTRY_H
#define SURICATA_PRIOR_STATE_REGISTRY_H

#include "suricata-common.h"
#include "app-layer-protos.h"

/** \brief Direction substitution codes for TransportHandshakeRule entries.
 *
 * The expander substitutes the author's five-tuple (SRC, SPORT, DST, DPORT)
 * into each handshake rule using one of these direction recipes.
 */
#define TH_DIR_CLIENT_TO_SERVER 1 /**< "<SRC> <SPORT> -> <DST> <DPORT>" */
#define TH_DIR_SERVER_TO_CLIENT 2 /**< "<DST> <DPORT> -> <SRC> <SPORT>" */
#define TH_DIR_BIDIR            3 /**< "<SRC> <SPORT> <> <DST> <DPORT>" */

/** \brief A single state in an app-layer protocol's state machine, as reported
 *         by the registry.
 *
 *  \note For protocols that do not register named states (DNS, NTP, SNMP,
 *        etc., where the parser's GetStateIdByName is NULL), the registry
 *        synthesises the four built-in hooks (request_started,
 *        request_complete, response_started, response_complete) and flags
 *        them with is_builtin=true.
 */
typedef struct StateMachineState_ {
    int progress;         /**< ordinal, as returned by GetStateIdByName */
    uint8_t direction;    /**< STREAM_TOSERVER | STREAM_TOCLIENT */
    const char *name;     /**< owned by the app-layer parser registry */
    bool is_builtin;      /**< request_started / request_complete / ... */
} StateMachineState;

/** \brief Summary info for an app-layer protocol's state machine.
 *
 *  \note Transports are no longer reported on this struct. Callers wanting
 *        the set of ipprotos registered for an alproto MUST call
 *        StateMachineRegistryGetSupportedTransports, which returns every
 *        registered transport in stable emission order (TCP, UDP, SCTP,
 *        others). This matters for multi-transport protocols like DNS
 *        (ALPROTO_DNS is registered on both IPPROTO_TCP and IPPROTO_UDP).
 */
typedef struct StateMachineInfo_ {
    AppProto alproto;
    int ts_complete;         /**< completion progress TOSERVER */
    int tc_complete;         /**< completion progress TOCLIENT */
    bool has_named_states;   /**< GetStateIdByName registered */
} StateMachineInfo;

/** \brief A single transport-handshake rule in a TransportHandshakeTemplate.
 *
 *  Each entry is a "rendering recipe" the expander instantiates with the
 *  author's five-tuple. `direction` selects how the five-tuple is written
 *  out, `condition_tail` is the option-block tail appended verbatim (for
 *  example "flow:to_server,not_established; flags:S,12;").
 */
typedef struct TransportHandshakeRule_ {
    const char *label;          /**< short audit label: "syn", "syn-ack", ... */
    uint8_t direction;          /**< TH_DIR_* */
    const char *condition_tail; /**< "" or "flow:...; flags:...;" */
} TransportHandshakeRule;

/** \brief Per-ipproto transport-handshake template.
 *
 *  Adding a new transport means registering a new entry keyed by `ipproto`
 *  in the in-tree table defined in prior-state-registry.c; no changes in
 *  the expander or validator are required.
 */
typedef struct TransportHandshakeTemplate_ {
    uint8_t ipproto;               /**< IPPROTO_TCP / _UDP / _SCTP / ... */
    const char *hook_proto;        /**< rendered in rule header, e.g. "tcp" */
    const TransportHandshakeRule *rules; /**< ordered list */
    int count;                     /**< number of rules (0 == placeholder) */
} TransportHandshakeTemplate;

/** \brief Does the given app-layer protocol expose a state machine the
 *         registry can reason about?
 *
 *  Returns true when the app-layer parser has registered a state-progress
 *  completion status for \p a on either direction (i.e., the protocol has
 *  been hooked up through AppLayerParserRegisterStateProgressCompletionStatus).
 *  Returns false for ALPROTO_UNKNOWN / ALPROTO_FAILED / unregistered values.
 */
bool StateMachineRegistryHasProtocol(AppProto a);

/** \brief Fill \p info with summary info for protocol \p a.
 *
 *  \retval 0 on success.
 *  \retval -1 if the protocol is not registered (info left untouched).
 */
int StateMachineRegistryGetInfo(AppProto a, StateMachineInfo *info);

/** \brief Resolve a hook name (e.g. "client_hello_done", "request_complete")
 *         to a concrete state on protocol \p a.
 *
 *  Resolves in both directions. Built-in hooks ("request_started",
 *  "request_complete", "response_started", "response_complete") are always
 *  resolved via the completion-status values even when the parser exposes
 *  named states of its own.
 *
 *  \retval 0 on success, \p out is filled with (progress, direction, name,
 *            is_builtin).
 *  \retval <0 on unknown or ambiguous hook (a hook name present in both the
 *            TS and TC tables for the same protocol). On failure an error
 *            message is written to (\p errbuf, \p errbuflen) when non-NULL.
 */
int StateMachineRegistryResolve(AppProto a, const char *hook_name,
        StateMachineState *out, char *errbuf, size_t errbuflen);

/** \brief Enumerate all states on direction \p direction of protocol \p a
 *         whose progress is strictly less than \p decision.
 *
 *  The output is ordered by ascending progress and is capped at \p max
 *  entries. The function returns the number of entries written.
 *
 *  \retval >=0 number of entries written.
 *  \retval <0 if the protocol is not registered or the direction is invalid.
 */
int StateMachineRegistryPrerequisites(AppProto a, uint8_t direction,
        int decision, StateMachineState *out, int max);

/** \brief Look up the (alproto, direction, progress) tuple at which a
 *         detection keyword becomes available.
 *
 *  Backed by the existing DetectEngineAppInspectionEngine registry:
 *  DetectAppLayerInspectEngineRegister() records a
 *  (buffer_name, alproto, direction, progress) tuple per keyword, and this
 *  function exposes that tuple. Used by PSV_KEYWORD_AFTER and
 *  PSV_KEYWORD_WRONG_DIR.
 *
 *  \retval 0 on success, out-params filled.
 *  \retval <0 on unknown keyword or when no active DetectEngineCtx exists.
 */
int StateMachineRegistryKeywordRequires(
        const char *keyword, AppProto *a, uint8_t *direction, int *progress);

/**
 * \brief Enumerate the ipprotos the given app-layer protocol is registered for,
 *        in stable emission order (TCP, UDP, SCTP, others).
 *
 * Writes up to \p max entries into \p out and returns the count written.
 * Returns <0 for an unregistered alproto. Examples:
 *   tls   -> { IPPROTO_TCP }
 *   dns   -> { IPPROTO_TCP, IPPROTO_UDP }
 *   snmp  -> { IPPROTO_UDP }
 */
int StateMachineRegistryGetSupportedTransports(AppProto a, uint8_t *out, int max);

/** \brief Fetch the transport-handshake template for \p ipproto.
 *
 *  Returns 0 on success with *\p out set to a non-NULL pointer into the
 *  in-tree template table. Returns \<0 if no template is registered for
 *  \p ipproto so the expander can skip Step 2 (Req 1.4).
 *
 *  \note A template registered with count==0 (placeholder, e.g. SCTP today)
 *        is returned with \<0 to match the "expander emits nothing" fall-
 *        through semantics described in design §Expansion Algorithm Step 2.
 */
int StateMachineRegistryGetTransportHandshakeTemplate(
        uint8_t ipproto, const TransportHandshakeTemplate **out);

#endif /* SURICATA_PRIOR_STATE_REGISTRY_H */

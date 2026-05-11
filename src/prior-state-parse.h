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
 * \brief Prior_State rule parser for the firewall "accept-prior-states"
 *        feature. Parses a classified rule line into a PriorStateRule IR,
 *        which the validator and expander then consume. See design
 *        §Components.2 for the contract.
 *
 * POC scope (Phase 1, tasks.md task 3): only the `<` operator form is
 * parsed here. The keyword form (`accept-prior-states;` in the options
 * block) and the form == PRIOR_STATE_KEYWORD code path are deferred to
 * Phase 2 (tasks.md task 11). The action is stored verbatim; the parser
 * does not reject non-`accept` actions or scopes outside {hook, flow, tx}
 * — that is the validator's job (PSV_BAD_ACTION, Phase 2 task 12).
 *
 * State resolution (mapping a state name like "client_hello_done" to a
 * concrete progress value / direction) is explicitly the validator's
 * responsibility (Task 4). The parser leaves decision_progress == 0 and
 * decision_direction == 0 as sentinel values.
 *
 * Neighbouring Suricata headers use the SURICATA_*_H include-guard style.
 */

#ifndef SURICATA_PRIOR_STATE_PARSE_H
#define SURICATA_PRIOR_STATE_PARSE_H

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "prior-state-classify.h"

/** \brief In-memory IR for a single Prior_State_Rule, constructed by
 *         PriorStateParseRule and consumed by the validator and expander.
 *
 *  Lifecycle: callers typically stack-allocate a zero-initialised struct,
 *  call PriorStateParseRule to fill it, then call PriorStateRuleClean when
 *  done. PriorStateRuleClean frees the heap-allocated string fields but
 *  not the struct itself (the caller owns the storage).
 *
 *  String-ownership notes:
 *   - `file` is a borrowed pointer: the caller (typically the rule-file
 *     loader) owns the string and must keep it alive for the lifetime of
 *     the PriorStateRule. The parser never copies it.
 *   - All other string pointers (`src_addr`, `src_port`, `dst_addr`,
 *     `dst_port`, `direction_op`, `msg`, `options_remainder`) are owned
 *     by the PriorStateRule and freed by PriorStateRuleClean.
 *   - `proto` and `state` are fixed-size inline char arrays.
 */
typedef struct PriorStateRule_ {
    /* source location — `file` is borrowed, not owned */
    const char *file;
    int lineno;

    /* action header */
    uint8_t action;       /**< ACTION_* flags (ACTION_ACCEPT expected, validator checks) */
    uint8_t action_scope; /**< ACTION_SCOPE_HOOK / _FLOW / _TX */

    /* decision hook */
    char proto[16];           /**< e.g. "tls", "dns", "http1" */
    char state[64];           /**< e.g. "client_hello_done" */
    AppProto alproto;         /**< resolved via AppLayerGetProtoByName */
    /** The set of transports the decision protocol is registered for,
     *  populated at parse time via
     *  StateMachineRegistryGetSupportedTransports. Emitted in the
     *  registry's stable order (TCP, UDP, SCTP, others) so Step 2 of
     *  the expander produces deterministic output across releases —
     *  TLS holds {IPPROTO_TCP}, SNMP holds {IPPROTO_UDP}, and DNS
     *  holds {IPPROTO_TCP, IPPROTO_UDP}. The expander iterates every
     *  entry so a single Prior_State_Rule permits the flow regardless
     *  of which transport the traffic actually arrives on (Req 1.3,
     *  1.5). Inline (no heap allocation); 4 slots is comfortably
     *  above any protocol registered today. */
    uint8_t transport_ipprotos[4];
    /** Number of valid entries in transport_ipprotos[]. Zero when
     *  alproto is ALPROTO_UNKNOWN (the validator will later reject
     *  with PSV_UNKNOWN_PROTO) or when the registry otherwise has no
     *  ipproto for the protocol; Step 2 of the expander treats
     *  count == 0 as "skip transport handshake emission", matching
     *  the SCTP placeholder fall-through already in place. */
    int transport_ipprotos_count;
    int decision_progress;    /**< resolved state id — 0 here, validator resolves */
    uint8_t decision_direction; /**< STREAM_TO* — 0 here, validator resolves */

    /* five-tuple, verbatim (owned heap strings) */
    char *src_addr;
    char *src_port;
    char *dst_addr;
    char *dst_port;
    char *direction_op;

    /* options (owned heap strings, may be NULL) */
    char *msg;                /**< unquoted msg value, or NULL if absent */
    uint32_t sid;             /**< required; parse fails if missing */
    uint32_t gid;             /**< default 1 */
    uint32_t rev;             /**< default 1 */
    char *options_remainder;  /**< detection keywords preserved verbatim,
                                *  already terminated by "; " separators,
                                *  suitable for the expander to splice
                                *  into the Decision_Hook rule's options
                                *  block. NULL if no detection keywords. */

    /* form used in the source line (for round-trip tests and error
     * messages). The POC always sets this to PRIOR_STATE_OPERATOR; the
     * PRIOR_STATE_KEYWORD code path lands in Phase 2 task 11. */
    PriorStateForm form;
} PriorStateRule;

/** \brief Parse a rule line into a PriorStateRule.
 *
 *  The caller must have already classified \p line as
 *  PRIOR_STATE_OPERATOR via PriorStateClassifyLine. This function does not
 *  re-classify.
 *
 *  On success, \p out is populated and the function returns 0. On failure
 *  the function returns a negative int, writes a descriptive message to
 *  \p errbuf (if non-NULL), and frees any heap allocations it made while
 *  parsing (so the caller need not call PriorStateRuleClean on a failed
 *  out-struct).
 *
 *  Error messages follow the existing Suricata rule-parse style (no
 *  file/lineno/sid prefix — those are the caller's responsibility at the
 *  loader error site, per design §Error Handling).
 *
 *  \param line     NUL-terminated rule-file line (one complete rule,
 *                  de-commented by the caller).
 *  \param file     Filename for \p out->file. Borrowed, never freed.
 *  \param lineno   Line number for \p out->lineno.
 *  \param out      Caller-owned output struct; zeroed on entry on success.
 *  \param errbuf   Error-message destination, or NULL.
 *  \param errbuflen Size of errbuf in bytes.
 *
 *  \retval  0 on success.
 *  \retval <0 on parse error.
 */
int PriorStateParseRule(const char *line, const char *file, int lineno,
        PriorStateRule *out, char *errbuf, size_t errbuflen);

/** \brief Release heap-allocated fields in a PriorStateRule.
 *
 *  Frees every SCStrdup'd field and zeroes the struct to avoid double
 *  free. Does NOT free the struct itself. Idempotent on an already-zeroed
 *  or already-cleaned struct.
 */
void PriorStateRuleClean(PriorStateRule *r);

#endif /* SURICATA_PRIOR_STATE_PARSE_H */

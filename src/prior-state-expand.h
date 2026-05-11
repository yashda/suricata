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
 * \brief Prior_State rule expander. Produces the concrete, loadable
 *        firewall-mode rule strings that Suricata's existing signature
 *        parser consumes, given a validated PriorStateRule. Implements
 *        the Step 0 → Step 5 algorithm from design §Expansion Algorithm.
 *
 * POC scope (Phase 1, tasks.md task 5): only `:tx` verdict scope is
 * expanded. `:hook` and `:flow` scopes are rejected at expansion time
 * with PRIOR_STATE_EXPAND_SCOPE_UNSUPPORTED. The `:hook` / `:flow`
 * branches are lifted in Phase 2 (tasks.md task 13).
 *
 * Transport-handshake rules are emitted for TCP (four rules: SYN,
 * SYN-ACK, ACK, post-handshake passthrough) and UDP (two directional
 * accepts, no `flow:` tail). SCTP and any other transport for which the
 * State_Machine_Registry has no template fall through silently — Step 2
 * emits nothing and the expander continues to Step 3 (Req 1.4).
 *
 * Output shape: the caller receives an ExpandedRuleList whose three
 * parallel arrays (`strings`, `labels`, `sub_indexes`) hold, for each
 * emitted rule, the loadable rule string, an audit-label, and the sub
 * index used in `{parent_sid}.{sub_index}` attribution rendering. The
 * list's `parent_sid` field carries the author's SID; the Decision_Hook
 * entry has sub_index 0, and prerequisite rules have sub_index 1..N in
 * emission order (transport-handshake rules first, then app-layer
 * prerequisite rules with decision-direction states ahead of
 * opposite-direction states, all in ascending-progress order). The
 * runtime SID for auto-accepted rules is derived deterministically from
 * (file path, parent_sid, sub_index) per design §Expansion Algorithm
 * Step 5; the formula is exposed via PriorStateExpandSubRuntimeSid so
 * the SID-collision validator (Phase 2 task 12) and the dump run mode
 * (task 7) can reproduce it.
 *
 * No provenance-table write happens in Phase 1 — the table is
 * introduced in tasks.md task 14. Phase 1 relies on the deterministic
 * formula alone.
 */

#ifndef SURICATA_PRIOR_STATE_EXPAND_H
#define SURICATA_PRIOR_STATE_EXPAND_H

#include "suricata-common.h"
#include "prior-state-parse.h"

/** \brief Output of PriorStateExpand.
 *
 *  All three per-rule arrays (`strings`, `labels`, `sub_indexes`) have
 *  `count` entries and use the same index space. They are allocated
 *  together in PriorStateExpand and released together in
 *  ExpandedRuleListFree.
 *
 *  - `strings[i]`     — heap-allocated NUL-terminated rule string, ready
 *                       for DetectFirewallRuleAppendNew. Owned by the list.
 *  - `labels[i]`      — heap-allocated NUL-terminated audit label. For
 *                       Step 2 rules this is the
 *                       TransportHandshakeRule.label ("syn", "udp-to-
 *                       server", ...); for Step 3 rules the app-layer
 *                       state name; the Decision_Hook entry carries an
 *                       empty string. Owned by the list.
 *  - `sub_indexes[i]` — 0 for the Decision_Hook entry, 1..N in emission
 *                       order for prerequisite rules.
 *
 *  Emission order (and therefore array index order):
 *    1. Transport-handshake rules (Step 2) in template order.
 *    2. App-layer prerequisite rules (Step 3): decision direction first
 *       by ascending progress, then opposite direction by ascending
 *       progress.
 *    3. Decision_Hook rule (Step 4) last.
 */
typedef struct ExpandedRuleList_ {
    char **strings;        /**< per-entry rule string, owned */
    char **labels;         /**< per-entry audit label, owned */
    uint16_t *sub_indexes; /**< per-entry sub index (0 = Decision_Hook) */
    int count;             /**< number of entries in every array */
    uint32_t parent_sid;   /**< author's SID (the Decision_Hook rule's sid) */
} ExpandedRuleList;

/** \brief Error codes returned by PriorStateExpand on failure.
 *
 *  On success PriorStateExpand returns 0. On failure it returns one of
 *  the negative codes below; errbuf (if non-NULL) is also populated with
 *  a human-readable detail string.
 */
#define PRIOR_STATE_EXPAND_OK                 0
#define PRIOR_STATE_EXPAND_ERR_NULL_INPUT     -1
#define PRIOR_STATE_EXPAND_SCOPE_UNSUPPORTED  -2
#define PRIOR_STATE_EXPAND_REGISTRY           -3
#define PRIOR_STATE_EXPAND_OOM                -4

/** \brief Compute the deterministic runtime SID for an auto-accepted
 *         expansion rule.
 *
 *  Mirrors the formula from design §Expansion Algorithm Step 5:
 *
 *      sub_runtime_sid = 0x80000000
 *                      | ((fnv1a32(file) ^ parent_sid ^ sub_index) & 0x7FFFFFFF)
 *
 *  The high bit is always set, reserving the upper half of the uint32
 *  SID space for expansion SIDs (the lower half [1, 2^31) remains
 *  available to authors). Sub index 0 (Decision_Hook) is not routed
 *  through this helper — the Decision_Hook rule keeps the author's
 *  original SID.
 *
 *  \param file       NUL-terminated source file path. NULL is tolerated
 *                    and treated as an empty string.
 *  \param parent_sid Author's SID from the Prior_State_Rule.
 *  \param sub_index  1..N, the prerequisite's ordinal in emission order.
 */
uint32_t PriorStateExpandSubRuntimeSid(const char *file, uint32_t parent_sid,
        uint16_t sub_index);

/** \brief Expand a validated PriorStateRule into a loadable rule list.
 *
 *  The validator (PriorStateValidate) must have run on \p r first so
 *  decision_progress / decision_direction are populated and the
 *  protocol / state names are known to the registry.
 *
 *  On success the caller owns \p *out and must free it with
 *  ExpandedRuleListFree. On failure \p *out is left NULL and \p errbuf
 *  (if non-NULL) is populated.
 *
 *  \param r          Validated PriorStateRule to expand. Must be non-NULL.
 *  \param out        Receives the newly-allocated list on success.
 *  \param errbuf     Optional error-message destination.
 *  \param errbuflen  Size of \p errbuf.
 *
 *  \retval PRIOR_STATE_EXPAND_OK on success.
 *  \retval <0 on error (see the PRIOR_STATE_EXPAND_ERR_* constants).
 */
int PriorStateExpand(const PriorStateRule *r, ExpandedRuleList **out, char *errbuf,
        size_t errbuflen);

/** \brief Release an ExpandedRuleList returned by PriorStateExpand.
 *
 *  Safe to call with NULL.
 */
void ExpandedRuleListFree(ExpandedRuleList *l);

#endif /* SURICATA_PRIOR_STATE_EXPAND_H */

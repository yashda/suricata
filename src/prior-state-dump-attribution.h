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
 * \brief Scratch attribution table used by the `--dump-expanded-rules`
 *        run mode. Carries the per-Expanded_Rule `(parent_sid, sub_index,
 *        label, decision_hook, src_file, src_lineno)` tuple the task 5
 *        expander surfaces on its ExpandedRuleList, so the dump run mode
 *        can render the design §Components.8 attribution comment above
 *        each emitted rule.
 *
 * This table is intentionally *not* the persistent SidProvenanceTable
 * introduced in tasks.md task 14. In Phase 1:
 *
 *   - The expander writes its scratch tuples into this table only when
 *     dump mode is active (PriorStateDumpAttributionIsEnabled() == true).
 *   - Non-dump loads leave the enable flag cleared and the record
 *     function becomes a no-op, so ordinary rule-load performance is
 *     unchanged.
 *   - The table is cleared at the start of each dump run and freed on
 *     shutdown. No eve / alert log path reads it; `--dump-expanded-rules`
 *     is the only consumer.
 *
 * Keyed by runtime SID because that is what Signature.id carries after
 * the expanded rule has been round-tripped through
 * DetectFirewallRuleAppendNew; it is also what the dump walker iterates
 * on. For the Decision_Hook entry the runtime SID equals the author's
 * parent_sid; for auto-accepted entries it is the deterministic value
 * from PriorStateExpandSubRuntimeSid. Both are deterministic per task 5.
 */

#ifndef SURICATA_PRIOR_STATE_DUMP_ATTRIBUTION_H
#define SURICATA_PRIOR_STATE_DUMP_ATTRIBUTION_H

#include "suricata-common.h"

/** \brief One scratch attribution record — matches the tuple the task 5
 *         expander surfaces on ExpandedRuleList.{sub_indexes,labels} plus
 *         the source location the loader contributes.
 *
 *  A zero-valued record means "no attribution recorded for this SID";
 *  the dump walker emits a bare rule with no leading attribution
 *  comment in that case (ordinary hand-written firewall rules).
 */
typedef struct PriorStateDumpAttribution_ {
    uint32_t parent_sid;       /**< author's SID from the Prior_State_Rule */
    uint16_t sub_index;        /**< 0 = Decision_Hook, 1..N = auto-accepted */
    bool is_decision_hook;     /**< true iff sub_index == 0 */
    uint32_t load_seq;         /**< 1..N in the order the expander emitted
                                *   its rules; 0 means uninitialised. Used
                                *   by the dump walker to render in load
                                *   order even though SCSigOrderSignatures
                                *   reshuffles de_ctx->sig_list by priority
                                *   before the dump runs. */
    char *label;               /**< audit label ("syn", "udp-to-server", a
                                *   state name, etc.) — may be empty for
                                *   the Decision_Hook. Owned by the table. */
    char *decision_hook;       /**< "<proto>:<state>" rendered once for the
                                *   Decision_Hook — NULL otherwise. Owned
                                *   by the table. */
    char *src_file;            /**< source rule-file path. Owned. */
    int src_lineno;            /**< source line number */
} PriorStateDumpAttribution;

/** \brief Enable the scratch attribution table and start fresh.
 *
 *  Must be called by the `--dump-expanded-rules` run mode *before* rule
 *  load, otherwise Record() is a no-op and the dump walker sees no
 *  attribution. Safe to call multiple times; each call clears any
 *  existing entries.
 */
void PriorStateDumpAttributionEnable(void);

/** \brief Release the scratch table and clear the enable flag. Idempotent. */
void PriorStateDumpAttributionDisable(void);

/** \brief Is the scratch attribution table currently accepting records?
 *
 *  Callers in the rule-load hot path (DetectPriorStateProcessLine) use
 *  this to skip the record step on ordinary non-dump loads — keeps the
 *  non-dump path free of attribution bookkeeping. */
bool PriorStateDumpAttributionIsEnabled(void);

/** \brief Record one attribution tuple for a runtime SID.
 *
 *  Called once per appended Expanded_Rule when dump mode is active. The
 *  helper takes a deep copy of \p label, \p decision_hook, and \p file so
 *  the caller can free its sources freely. Silently ignored when
 *  PriorStateDumpAttributionIsEnabled() is false.
 *
 *  \param runtime_sid    The loaded Signature's `id`. Table key.
 *  \param parent_sid     Author's SID from the Prior_State_Rule.
 *  \param sub_index      0 for the Decision_Hook rule; 1..N for prereqs.
 *  \param label          Audit label from ExpandedRuleList.labels[i];
 *                        empty string allowed; never NULL.
 *  \param decision_hook  "<proto>:<state>" for the Decision_Hook entry
 *                        (sub_index == 0), NULL otherwise.
 *  \param file           Source rule-file path.
 *  \param lineno         Source line number.
 */
void PriorStateDumpAttributionRecord(uint32_t runtime_sid, uint32_t parent_sid,
        uint16_t sub_index, const char *label, const char *decision_hook, const char *file,
        int lineno);

/** \brief Look up the attribution record for a runtime SID.
 *
 *  Returns NULL if no record exists (either because dump mode is off or
 *  because the SID belongs to a hand-written rule). The returned pointer
 *  is valid until the next PriorStateDumpAttributionDisable() or
 *  PriorStateDumpAttributionEnable() call.
 */
const PriorStateDumpAttribution *PriorStateDumpAttributionLookup(uint32_t runtime_sid);

#endif /* SURICATA_PRIOR_STATE_DUMP_ATTRIBUTION_H */

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
 * \brief Prior_State validator for the firewall "accept-prior-states"
 *        feature. Runs the load-time checks driven by Requirements 4, 5,
 *        6, 7, 8 against a parsed PriorStateRule, resolves the decision
 *        hook to a concrete (progress, direction) pair, and emits
 *        structured error messages on rejection. See design §Components.4.
 *
 * POC scope (Phase 1, tasks.md task 4): only the three registry-backed
 * checks the user would hit if they typo'd a protocol or state during a
 * demo are implemented:
 *
 *   - PSV_UNKNOWN_PROTO — StateMachineRegistryHasProtocol() returns false.
 *   - PSV_UNKNOWN_STATE — StateMachineRegistryResolve() fails.
 *   - PSV_INITIAL_STATE — Decision_Hook has no prerequisite states in its
 *                         direction.
 *
 * The remaining six check IDs (PSV_FORM_CONFLICT, PSV_BAD_ACTION,
 * PSV_KEYWORD_AFTER, PSV_KEYWORD_WRONG_DIR, PSV_DIRECTION_MISMATCH,
 * PSV_SID_COLLISION) are declared in the enum so callers and tests can
 * reference them today, but their check bodies are deferred to Phase 2
 * (tasks.md task 12). Calling PriorStateValidate() on a rule that would
 * fail one of those deferred checks currently returns PSV_OK.
 *
 * Side-effect note: the validator is the component that resolves the
 * decision_hook name to a concrete progress value and direction on the
 * rule's protocol. The parser (see prior-state-parse.h) intentionally
 * leaves decision_progress and decision_direction as zero sentinels; the
 * validator fills those fields on success so the expander has the
 * resolved state data it needs to run. This matches the "validator
 * resolves" contract documented in the parser header.
 *
 * Error emission: on every rejection the validator calls SCLogError()
 * with the canonical rule-load error format
 *
 *     fw: <file>:<lineno>: sid:<parent_sid>: <PSV_*>: <detail>
 *
 * and — when \p errbuf is non-NULL — also writes the same message into
 * the caller's buffer so unit tests can assert on it without capturing
 * log output. The rule-load bad-sig counter lives on the stack inside
 * DetectLoadSigFile; the caller that wires the validator into the loader
 * (Phase 1 task 6) is responsible for incrementing that counter when
 * PriorStateValidate() returns a non-PSV_OK value, which preserves the
 * existing rule-load error semantics (Req 8.5).
 *
 * Neighbouring Suricata headers use the SURICATA_*_H include-guard style,
 * matching the other prior-state-* headers already in the tree.
 */

#ifndef SURICATA_PRIOR_STATE_VALIDATE_H
#define SURICATA_PRIOR_STATE_VALIDATE_H

#include "suricata-common.h"
#include "prior-state-parse.h"

/** \brief Result of PriorStateValidate().
 *
 *  PSV_OK (0) means the rule passed every implemented check and the
 *  validator populated \p r->decision_progress and
 *  \p r->decision_direction. Any non-zero value is the identifier of the
 *  first failing check, in the order listed in design §Components.4.
 *
 *  The enum carries all nine check IDs (three implemented in POC, six
 *  deferred to Phase 2) so callers and tests can pattern-match on the
 *  full set today. Stringify with PriorStateValidationResultName().
 */
typedef enum {
    PSV_OK = 0,             /**< no error, rule is valid */
    PSV_FORM_CONFLICT,      /**< both '<' operator and keyword present (Phase 2) */
    PSV_BAD_ACTION,         /**< action/scope not in {accept:hook,flow,tx} (Phase 2) */
    PSV_UNKNOWN_PROTO,      /**< POC: protocol not in State_Machine_Registry */
    PSV_UNKNOWN_STATE,      /**< POC: state not in State_Machine_Registry for protocol */
    PSV_INITIAL_STATE,      /**< POC: decision hook has no prerequisites on its direction */
    PSV_KEYWORD_AFTER,      /**< detection keyword requires state past decision (Phase 2) */
    PSV_KEYWORD_WRONG_DIR,  /**< detection keyword requires direction outside D (Phase 2) */
    PSV_DIRECTION_MISMATCH, /**< five-tuple direction incompatible with reachable states (Phase 2) */
    PSV_SID_COLLISION,      /**< produced Sub_SID collides with an existing SID (Phase 2) */
} PriorStateValidationResult;

/** \brief Return a stable, NUL-terminated string name for a
 *         PriorStateValidationResult value — e.g. "PSV_UNKNOWN_STATE".
 *
 *  Used both for the `<PSV_*>` field in the emitted error message and by
 *  tests asserting on the specific check that rejected a rule. Values
 *  outside the known range return the literal string "PSV_UNKNOWN".
 */
const char *PriorStateValidationResultName(PriorStateValidationResult r);

/** \brief Run the load-time checks against a parsed PriorStateRule.
 *
 *  On success (return value PSV_OK), the function writes the resolved
 *  decision_progress and decision_direction into \p r (the two fields
 *  the parser left as zero sentinels) so the expander can emit
 *  Step-1 prerequisite rules without re-resolving.
 *
 *  On failure, the function emits the structured error via SCLogError()
 *  in the format
 *
 *     fw: <file>:<lineno>: sid:<parent_sid>: <PSV_*>: <detail>
 *
 *  If \p errbuf is non-NULL the same message is also copied into
 *  (\p errbuf, \p errbuflen). The rule struct is not mutated on failure.
 *
 *  The function does not touch any global Suricata state and does not
 *  allocate. It is safe to call from rule-load code paths without
 *  additional synchronisation.
 *
 *  \param r          Parsed rule from PriorStateParseRule. Must be non-NULL.
 *                    On PSV_OK, decision_progress and decision_direction
 *                    are populated as a side effect.
 *  \param errbuf     Optional destination buffer for the error message.
 *  \param errbuflen  Size of \p errbuf in bytes.
 *
 *  \retval PSV_OK on success.
 *  \retval PSV_UNKNOWN_PROTO / PSV_UNKNOWN_STATE / PSV_INITIAL_STATE on
 *          the respective POC-scope rejection. Phase-2 check IDs are
 *          reserved in the enum but never returned by the POC validator.
 */
PriorStateValidationResult PriorStateValidate(
        PriorStateRule *r, char *errbuf, size_t errbuflen);

#endif /* SURICATA_PRIOR_STATE_VALIDATE_H */

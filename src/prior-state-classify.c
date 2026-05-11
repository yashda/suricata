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
 * \brief Prior_State line classifier implementation. See
 *        prior-state-classify.h for the contract.
 *
 * POC scope (Phase 1, tasks.md task 2): only the `<` operator form is
 * recognised. The keyword form (`accept-prior-states;`) and the both-forms
 * error path are declared in the PriorStateForm enum but are deferred to
 * Phase 2 (task 10); any line that uses only the keyword form classifies as
 * PRIOR_STATE_NONE and falls through to the existing rule-loader path
 * unchanged.
 *
 * Hot-path constraint: the common case (non-Prior_State lines) must add no
 * measurable cost. The implementation is a single forward byte scan over
 * the rule header (the portion before the first unquoted '('). It never
 * allocates, never calls into libc beyond the byte-level predicates, and
 * never uses regex.
 */

#include "suricata-common.h"
#include "prior-state-classify.h"

/** \brief Is \p c an ASCII letter — the first character of a `proto:state`
 *         token? Kept protocol-agnostic: protocol names in Suricata's
 *         app-layer registry (`tls`, `http1`, `dns`, `ssh`, `ntp`, ...) are
 *         all lowercase ASCII letters, but we accept upper-case too for
 *         defensive parity with how other tokenisers in the tree treat
 *         protocol names.
 */
static inline bool IsProtoNameStart(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/** \brief Classify a rule-file line.
 *
 *  POC algorithm (operator-only):
 *    1. If \p line is NULL, empty, or (after skipping leading whitespace)
 *       starts with '#' (comment), return PRIOR_STATE_NONE.
 *    2. Scan forward tracking whether we are inside a `"..."` quoted
 *       segment and whether we have just seen whitespace.
 *    3. Stop at the first unquoted '(' — that marks the start of the
 *       options block, everything before is the rule header, and the
 *       operator form only ever appears in the header.
 *    4. Within the header, a '<' byte classifies the line as
 *       PRIOR_STATE_OPERATOR when:
 *         * it is not inside quotes, and
 *         * the previous non-quote byte was whitespace, and
 *         * the next byte is an ASCII letter (the first character of a
 *           `proto:state` token).
 *       The `<>` bidirectional operator is excluded by the
 *       "next byte is a letter" requirement (its '<' is followed by '>').
 *    5. Anything else (header with no operator, keyword-form lines, etc.)
 *       returns PRIOR_STATE_NONE in the POC.
 */
PriorStateForm PriorStateClassifyLine(const char *line)
{
    if (line == NULL) {
        return PRIOR_STATE_NONE;
    }

    /* Skip leading whitespace. */
    const char *p = line;
    while (*p == ' ' || *p == '\t') {
        p++;
    }

    /* Empty line or comment. */
    if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#') {
        return PRIOR_STATE_NONE;
    }

    /* Walk forward through the header (up to the first unquoted '(') looking
     * for an operator-form '<'. prev_was_ws seeds to true because the very
     * first non-whitespace token — the action (e.g. "accept:tx") — is
     * definitionally preceded by start-of-line, which is as good as
     * whitespace for our "operator appears between two tokens" check
     * semantics. It gets flipped to false on the first non-whitespace byte
     * and updated normally from there.
     */
    bool in_quotes = false;
    bool prev_was_ws = true;

    for (; *p != '\0' && *p != '\n' && *p != '\r'; p++) {
        char c = *p;

        if (in_quotes) {
            /* Only a closing '"' ends the quoted segment. Everything else
             * inside quotes is opaque to the classifier — including any
             * '<' bytes, which is the defensive case the spec calls out
             * for content values like content:"<script>".
             */
            if (c == '"') {
                in_quotes = false;
                prev_was_ws = false;
            }
            continue;
        }

        if (c == '"') {
            in_quotes = true;
            prev_was_ws = false;
            continue;
        }

        if (c == '(') {
            /* End of header. Options block starts here; the operator form
             * never appears past this point. POC returns NONE because
             * keyword-form detection is deferred to Phase 2 task 10.
             */
            return PRIOR_STATE_NONE;
        }

        if (c == ' ' || c == '\t') {
            prev_was_ws = true;
            continue;
        }

        if (c == '<' && prev_was_ws) {
            /* Candidate operator byte. Distinguish from `<>` (bidirectional
             * direction operator) by requiring the following byte to be an
             * ASCII letter (the first character of a proto name).
             */
            char next = *(p + 1);
            if (IsProtoNameStart(next)) {
                return PRIOR_STATE_OPERATOR;
            }
            /* Not the operator form. Fall through; continue scanning in
             * case a later '<' in the header is the real operator. */
            prev_was_ws = false;
            continue;
        }

        prev_was_ws = false;
    }

    /* Reached end of line without seeing an unquoted '(' or an operator
     * '<' that satisfied the form check.
     */
    return PRIOR_STATE_NONE;
}

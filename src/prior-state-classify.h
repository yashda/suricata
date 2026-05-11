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
 * \brief Prior_State line classifier for the firewall "accept-prior-states"
 *        feature. A cheap first-pass textual test over a raw rule line that
 *        decides whether the line carries either of the two feature syntaxes
 *        (the `<` operator in the header, or the `accept-prior-states;`
 *        keyword in the options block). See design §Components.1.
 *
 * This is the hot-path gate: the vast majority of lines in a real rule file
 * are ordinary (non-Prior_State) rules, and must pay no measurable classifier
 * cost. The implementation uses a short-circuit byte scan over the rule
 * header only, never a regex.
 *
 * POC scope (this file): only PRIOR_STATE_OPERATOR is populated by
 * PriorStateClassifyLine. The PRIOR_STATE_KEYWORD and PRIOR_STATE_BOTH enum
 * values are declared here but the detection logic for them is deferred to
 * Phase 2 (tasks.md task 10). Lines carrying only the keyword form classify
 * as PRIOR_STATE_NONE in the POC and therefore fall through to the existing
 * rule-load path unchanged.
 *
 * Neighbouring Suricata headers use the SURICATA_*_H include-guard style,
 * matching the rest of the tree and matching the prior-state-registry.h
 * file created in tasks.md task 1.
 */

#ifndef SURICATA_PRIOR_STATE_CLASSIFY_H
#define SURICATA_PRIOR_STATE_CLASSIFY_H

#include "suricata-common.h"

/** \brief Classification of a raw rule-file line under the Prior_State
 *         feature.
 *
 *  Values intentionally form a 2-bit set where bit 0 indicates the
 *  `<` operator form and bit 1 indicates the `accept-prior-states;`
 *  keyword form. Downstream code may rely on that layout for form-conflict
 *  checks (Req 2.3); the explicit PRIOR_STATE_BOTH constant is provided so
 *  callers do not need to depend on that representation directly.
 */
typedef enum {
    PRIOR_STATE_NONE = 0,     /**< ordinary rule, pass through */
    PRIOR_STATE_OPERATOR = 1, /**< header contains `<proto:state` */
    PRIOR_STATE_KEYWORD = 2,  /**< options contain `accept-prior-states;` */
    PRIOR_STATE_BOTH = 3,     /**< both forms present (rejected per Req 2.3) */
} PriorStateForm;

/** \brief Classify a raw rule-file line as one of the PriorStateForm values.
 *
 *  The classifier is pure: it takes a NUL-terminated C string and returns a
 *  PriorStateForm. It never allocates, never mutates its input, and never
 *  performs I/O.
 *
 *  POC behaviour (Phase 1, operator-only):
 *    - Returns PRIOR_STATE_OPERATOR when the rule header (the portion before
 *      the first unquoted '(') contains a '<' byte that is
 *        * preceded by at least one whitespace character, and
 *        * immediately followed by an ASCII letter (the start of a
 *          `proto:state` token).
 *      This distinguishes the Prior_State operator from the `<>`
 *      bidirectional direction operator (whose '<' is followed by '>') and
 *      from the `->` direction operator (which contains no '<').
 *    - Returns PRIOR_STATE_NONE for every other line, including blank
 *      lines, lines whose first non-whitespace character is '#' (comments),
 *      lines with no '(' at all, and any line that only uses the
 *      `accept-prior-states;` keyword form (that surface is deferred to
 *      Phase 2 task 10).
 *
 *  Scanning skips '<' bytes that fall inside paired '"' characters so a
 *  quoted value in the header (uncommon, but possible defensively) cannot
 *  produce a false positive.
 *
 *  \param line NUL-terminated rule-file line. NULL is tolerated and
 *              classified as PRIOR_STATE_NONE.
 *  \retval PRIOR_STATE_NONE     for ordinary lines, blanks, comments, and
 *                               (in the POC) keyword-only lines.
 *  \retval PRIOR_STATE_OPERATOR for lines carrying the `<` operator form.
 */
PriorStateForm PriorStateClassifyLine(const char *line);

#endif /* SURICATA_PRIOR_STATE_CLASSIFY_H */

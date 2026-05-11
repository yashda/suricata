/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * \author Eileen Donlon <emdonlo@gmail.com>
 */

#ifndef SURICATA_DETECT_ENGINE_ANALYZER_H
#define SURICATA_DETECT_ENGINE_ANALYZER_H

#include <stdint.h>

struct DetectEngineCtx_;

void SetupEngineAnalysis(struct DetectEngineCtx_ *de_ctx, bool *, bool *);
void CleanupEngineAnalysis(struct DetectEngineCtx_ *de_ctx);

void EngineAnalysisFP(const struct DetectEngineCtx_ *de_ctx, const Signature *s, const char *line);
void EngineAnalysisRules(
        const struct DetectEngineCtx_ *de_ctx, const Signature *s, const char *line);
void EngineAnalysisRulesFailure(
        const struct DetectEngineCtx_ *de_ctx, const char *line, const char *file, int lineno);

void EngineAnalysisRules2(const struct DetectEngineCtx_ *de_ctx, const Signature *s);

int FirewallAnalyzer(const struct DetectEngineCtx_ *de_ctx);

/** \brief Reconstruct a loadable firewall-mode rule string for a single
 *         Signature.
 *
 *  Used by the `--dump-expanded-rules` run mode (see suricata.c) and by
 *  `--engine-analysis` to round-trip an in-memory Signature back to a
 *  line that a human can paste into a rule file. Per design §Components.7
 *  the POC scope of this helper is narrowed to the Expanded_Rule shapes
 *  the Phase 1 expander produces (tasks.md task 7):
 *
 *    - Transport-handshake rules under `tcp:all` / `udp:all`.
 *    - App-layer prerequisite rules under `<proto>:<state>`.
 *    - The Decision_Hook rule under `accept:tx <proto>:<state>` with the
 *      author's five-tuple and options preserved verbatim.
 *
 *  Implementation: we emit the Signature's stored `sig_str`, which is
 *  the exact rule string that was fed to DetectFirewallRuleAppendNew at
 *  load time (the parser captures it via SCStrdup in SigInitHelper).
 *  This is byte-identical to what the expander emitted for Prior_State
 *  rules, which satisfies Req 9.2 and matches the worked examples in
 *  design §Worked Examples. Extending this helper to cover the remaining
 *  option-keyword shapes, `:hook` and `:flow` scopes, the keyword-form
 *  source line, and collision-error paths lands in Phase 2 task 16.
 *
 *  \param s    The loaded Signature. Must be non-NULL. `s->sig_str` must
 *              be non-NULL (it is, for every rule that comes through
 *              SigInitHelper).
 *  \param buf  Destination buffer. NUL-terminated on success. Must be
 *              non-NULL when \p len > 0.
 *  \param len  Size of \p buf in bytes.
 *
 *  \retval  >0 number of bytes written to \p buf (excluding the NUL).
 *  \retval  -1 on invalid inputs or if \p buf is too small.
 */
int SignatureToRuleString(const Signature *s, char *buf, size_t len);

#endif /* SURICATA_DETECT_ENGINE_ANALYZER_H */

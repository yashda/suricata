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
 * \brief Prior_State validator implementation. See prior-state-validate.h
 *        for the contract and the POC vs Phase-2 scope boundary.
 *
 * The POC implements three of the nine PSV_* checks — the ones a rule
 * author would hit by typo'ing a protocol name, a state name, or pointing
 * at the initial state of a direction. The other six check IDs are
 * reserved in the enum and their bodies land in Phase 2 (task 12).
 */

#include "suricata-common.h"
#include "prior-state-validate.h"

#include "app-layer-protos.h"
#include "prior-state-registry.h"

#include "util-debug.h"

/* -------------------------------------------------------------------------
 * Stringification
 * ------------------------------------------------------------------------- */

const char *PriorStateValidationResultName(PriorStateValidationResult r)
{
    switch (r) {
        case PSV_OK:
            return "PSV_OK";
        case PSV_FORM_CONFLICT:
            return "PSV_FORM_CONFLICT";
        case PSV_BAD_ACTION:
            return "PSV_BAD_ACTION";
        case PSV_UNKNOWN_PROTO:
            return "PSV_UNKNOWN_PROTO";
        case PSV_UNKNOWN_STATE:
            return "PSV_UNKNOWN_STATE";
        case PSV_INITIAL_STATE:
            return "PSV_INITIAL_STATE";
        case PSV_KEYWORD_AFTER:
            return "PSV_KEYWORD_AFTER";
        case PSV_KEYWORD_WRONG_DIR:
            return "PSV_KEYWORD_WRONG_DIR";
        case PSV_DIRECTION_MISMATCH:
            return "PSV_DIRECTION_MISMATCH";
        case PSV_SID_COLLISION:
            return "PSV_SID_COLLISION";
    }
    return "PSV_UNKNOWN";
}

/* -------------------------------------------------------------------------
 * Error emission
 * ------------------------------------------------------------------------- */

/** \brief Format a validator error into a local buffer, emit it via
 *         SCLogError, and copy the formatted text into the caller's
 *         \p errbuf if provided.
 *
 *  The message format — fixed across every validator rejection — is
 *
 *     fw: <file>:<lineno>: sid:<parent_sid>: <PSV_*>: <detail>
 *
 *  matching design §Error Handling. \p file is what the parser captured
 *  from the rule-file loader; it may be NULL if the caller is feeding
 *  the validator a synthesised PriorStateRule (for example a unit test),
 *  in which case we substitute "<unknown>" so the message stays
 *  well-formed.
 */
static void EmitValidationError(const PriorStateRule *r, PriorStateValidationResult code,
        char *errbuf, size_t errbuflen, const char *fmt, ...)
        __attribute__((format(printf, 5, 6)));

static void EmitValidationError(const PriorStateRule *r, PriorStateValidationResult code,
        char *errbuf, size_t errbuflen, const char *fmt, ...)
{
    /* 1024 bytes is generous for any realistic combination of
     * file/lineno/sid plus the detail string; avoids heap allocation on
     * a cold path. */
    char detail[512];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);

    char message[1024];
    const char *file = (r != NULL && r->file != NULL) ? r->file : "<unknown>";
    const int lineno = (r != NULL) ? r->lineno : 0;
    const uint32_t sid = (r != NULL) ? r->sid : 0;
    (void)snprintf(message, sizeof(message), "fw: %s:%d: sid:%" PRIu32 ": %s: %s", file, lineno,
            sid, PriorStateValidationResultName(code), detail);

    SCLogError("%s", message);

    if (errbuf != NULL && errbuflen > 0) {
        (void)snprintf(errbuf, errbuflen, "%s", message);
    }
}

/* -------------------------------------------------------------------------
 * POC checks (registry-backed)
 * -------------------------------------------------------------------------
 *
 * The checks run in the order defined in design §Components.4. The POC
 * implements checks 3–5 (UNKNOWN_PROTO, UNKNOWN_STATE, INITIAL_STATE),
 * all of which require the State_Machine_Registry to answer. Checks 1–2
 * and 6–9 are Phase-2 work and are skipped here.
 */

/** \brief PSV_UNKNOWN_PROTO — the rule names a protocol not present in
 *         the State_Machine_Registry. */
static PriorStateValidationResult CheckUnknownProto(
        const PriorStateRule *r, char *errbuf, size_t errbuflen)
{
    if (r->alproto == ALPROTO_UNKNOWN || !StateMachineRegistryHasProtocol(r->alproto)) {
        EmitValidationError(r, PSV_UNKNOWN_PROTO, errbuf, errbuflen,
                "protocol '%s' is not registered in the state-machine registry", r->proto);
        return PSV_UNKNOWN_PROTO;
    }
    return PSV_OK;
}

/** \brief PSV_UNKNOWN_STATE — the rule names a state that does not exist
 *         on its protocol. On success, writes the resolved
 *         (progress, direction) into \p r. */
static PriorStateValidationResult CheckUnknownState(
        PriorStateRule *r, char *errbuf, size_t errbuflen)
{
    StateMachineState st;
    memset(&st, 0, sizeof(st));
    char resolve_err[256];
    resolve_err[0] = '\0';
    if (StateMachineRegistryResolve(r->alproto, r->state, &st, resolve_err, sizeof(resolve_err)) <
            0) {
        const char *detail = (resolve_err[0] != '\0')
                                     ? resolve_err
                                     : "state name not recognised for this protocol";
        EmitValidationError(r, PSV_UNKNOWN_STATE, errbuf, errbuflen,
                "protocol '%s' has no state named '%s' (%s)", r->proto, r->state, detail);
        return PSV_UNKNOWN_STATE;
    }

    /* Publish the resolution for the expander. */
    r->decision_progress = st.progress;
    r->decision_direction = st.direction;
    return PSV_OK;
}

/** \brief PSV_INITIAL_STATE — the decision hook is the initial state on
 *         its direction and therefore has no prerequisite states. The
 *         Prior_State feature requires at least one prerequisite state
 *         to expand, so this is rejected at load time per Req 5.4 / 8.3.
 *
 *  \note This must run after CheckUnknownState because it relies on
 *        decision_progress and decision_direction having been resolved. */
static PriorStateValidationResult CheckInitialState(
        const PriorStateRule *r, char *errbuf, size_t errbuflen)
{
    /* Two cases describe "no prerequisites on the decision direction":
     *
     *   1. decision_progress == 0 AND the decision direction has no
     *      state with a lower progress (by construction there is none —
     *      progress 0 is the first). This covers every initial state
     *      regardless of whether the protocol uses named states or only
     *      the four built-in hooks.
     *
     *   2. decision_progress > 0 but the registry reports no states
     *      before it. This can happen if a protocol registers its state
     *      table with a gap, which we treat as equivalent to "initial"
     *      for the purpose of this check.
     *
     *  We ask the registry directly so the check is driven by whatever
     *  states the adapter would actually emit in Step 1 of the expansion
     *  algorithm, keeping this check symmetric with the expander.
     */
    StateMachineState prereqs[32];
    memset(prereqs, 0, sizeof(prereqs));
    const int n = StateMachineRegistryPrerequisites(r->alproto, r->decision_direction,
            r->decision_progress, prereqs, (int)(sizeof(prereqs) / sizeof(prereqs[0])));
    if (n <= 0) {
        EmitValidationError(r, PSV_INITIAL_STATE, errbuf, errbuflen,
                "hook '%s:%s' is the initial state on its direction and has no prerequisite states",
                r->proto, r->state);
        return PSV_INITIAL_STATE;
    }
    return PSV_OK;
}

/* -------------------------------------------------------------------------
 * Public entry point
 * ------------------------------------------------------------------------- */

PriorStateValidationResult PriorStateValidate(
        PriorStateRule *r, char *errbuf, size_t errbuflen)
{
    if (r == NULL) {
        /* Defensive: callers should never pass NULL, but returning a
         * well-known rejection value is safer than crashing. We cannot
         * emit a file/lineno-qualified error here because we have no
         * rule to name. */
        if (errbuf != NULL && errbuflen > 0) {
            (void)snprintf(errbuf, errbuflen,
                    "fw: <unknown>:0: sid:0: PSV_UNKNOWN_PROTO: NULL PriorStateRule");
        }
        SCLogError("fw: <unknown>:0: sid:0: PSV_UNKNOWN_PROTO: NULL PriorStateRule");
        return PSV_UNKNOWN_PROTO;
    }

    /* Phase-2 checks (PSV_FORM_CONFLICT, PSV_BAD_ACTION) are intentionally
     * skipped in the POC per task 4's scope. They are reserved in the
     * enum so callers and tests can pattern-match on them, but their
     * bodies land in task 12. */

    PriorStateValidationResult rc;

    rc = CheckUnknownProto(r, errbuf, errbuflen);
    if (rc != PSV_OK) {
        return rc;
    }

    rc = CheckUnknownState(r, errbuf, errbuflen);
    if (rc != PSV_OK) {
        return rc;
    }

    rc = CheckInitialState(r, errbuf, errbuflen);
    if (rc != PSV_OK) {
        return rc;
    }

    /* Phase-2 keyword / direction / sid-collision checks land in task 12. */

    return PSV_OK;
}

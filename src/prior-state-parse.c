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
 * \brief Prior_State rule parser implementation. See prior-state-parse.h
 *        for the contract.
 *
 * POC scope (Phase 1, tasks.md task 3): only the `<` operator form is
 * parsed. The keyword form is deferred to Phase 2 (task 11).
 */

#include "suricata-common.h"
#include "prior-state-parse.h"

#include "action-globals.h"
#include "app-layer.h"
#include "app-layer-protos.h"
#include "prior-state-registry.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-mem.h"

/* -------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------- */

/** \brief Write a formatted error message to \p errbuf if non-NULL. */
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

/** \brief Advance \p *pp past ASCII whitespace (space, tab). */
static void SkipWs(const char **pp)
{
    const char *p = *pp;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    *pp = p;
}

/** \brief Tokeniser for rule-header five-tuple parsing.
 *
 *  Reads the next whitespace-separated token from \p *pp into \p out,
 *  respecting `[...]` grouping (for address and port lists such as
 *  `[192.168.0.0/24,10.0.0.0/8]`) and `"..."` quoted strings.
 *
 *  Advances \p *pp past the emitted token on success; on failure the
 *  pointer is left at the position that triggered the failure so the
 *  caller can report it.
 *
 *  \retval 0 on success.
 *  \retval -1 on "no more tokens" or buffer overflow.
 */
static int NextHeaderToken(const char **pp, char *out, size_t out_sz)
{
    SkipWs(pp);
    const char *p = *pp;
    if (*p == '\0') {
        return -1;
    }

    const char *start = p;
    int bracket_depth = 0;
    bool in_quotes = false;

    while (*p != '\0') {
        char c = *p;
        if (in_quotes) {
            if (c == '"') {
                in_quotes = false;
            }
            p++;
            continue;
        }
        if (c == '"') {
            in_quotes = true;
            p++;
            continue;
        }
        if (c == '[') {
            bracket_depth++;
            p++;
            continue;
        }
        if (c == ']') {
            if (bracket_depth > 0) {
                bracket_depth--;
            }
            p++;
            continue;
        }
        if (bracket_depth == 0 && (c == ' ' || c == '\t')) {
            break;
        }
        p++;
    }

    size_t len = (size_t)(p - start);
    if (len >= out_sz) {
        return -1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    *pp = p;
    return 0;
}

/* -------------------------------------------------------------------------
 * Action parsing
 * ------------------------------------------------------------------------- */

/** \brief Map an action name to an ACTION_* flag.
 *
 *  Mirrors ActionStringToFlags in detect-parse.c but without
 *  libnet capability checks (those are the validator/loader's concern,
 *  not the IR builder's). Returns 0 on unknown action.
 */
static uint8_t ActionNameToFlag(const char *name)
{
    if (strcasecmp(name, "accept") == 0)
        return ACTION_ACCEPT;
    if (strcasecmp(name, "alert") == 0)
        return ACTION_ALERT;
    if (strcasecmp(name, "drop") == 0)
        return ACTION_DROP;
    if (strcasecmp(name, "pass") == 0)
        return ACTION_PASS;
    if (strcasecmp(name, "reject") == 0 || strcasecmp(name, "rejectsrc") == 0)
        return ACTION_REJECT;
    if (strcasecmp(name, "rejectdst") == 0)
        return ACTION_REJECT_DST;
    if (strcasecmp(name, "rejectboth") == 0)
        return ACTION_REJECT_BOTH;
    if (strcasecmp(name, "config") == 0)
        return ACTION_CONFIG;
    return 0;
}

/** \brief Map a scope name (the part after the ':' in "action:scope") to
 *         an ACTION_SCOPE_* enum value.
 *
 *  Returns \c ACTION_SCOPE_AUTO (0) when \p name is unrecognised. The
 *  validator (Phase 2, PSV_BAD_ACTION) is the gate that rejects bad
 *  scopes; the parser is permissive and only fails on completely
 *  structurally invalid tokens.
 */
static uint8_t ScopeNameToFlag(const char *name)
{
    if (strcmp(name, "hook") == 0)
        return (uint8_t)ACTION_SCOPE_HOOK;
    if (strcmp(name, "flow") == 0)
        return (uint8_t)ACTION_SCOPE_FLOW;
    if (strcmp(name, "tx") == 0)
        return (uint8_t)ACTION_SCOPE_TX;
    if (strcmp(name, "packet") == 0)
        return (uint8_t)ACTION_SCOPE_PACKET;
    return (uint8_t)ACTION_SCOPE_AUTO;
}

/** \brief Parse an action token like "accept:tx" into (action, scope). */
static int ParseActionToken(const char *tok, uint8_t *action_out, uint8_t *scope_out,
        char *errbuf, size_t errbuflen)
{
    char name[32];
    char scope[32];
    name[0] = '\0';
    scope[0] = '\0';

    const char *colon = strchr(tok, ':');
    size_t name_len = colon ? (size_t)(colon - tok) : strlen(tok);
    if (name_len == 0 || name_len >= sizeof(name)) {
        SetErr(errbuf, errbuflen, "invalid action token '%s'", tok);
        return -1;
    }
    memcpy(name, tok, name_len);
    name[name_len] = '\0';

    if (colon) {
        const char *s = colon + 1;
        size_t slen = strlen(s);
        if (slen == 0 || slen >= sizeof(scope)) {
            SetErr(errbuf, errbuflen, "invalid action scope in token '%s'", tok);
            return -1;
        }
        memcpy(scope, s, slen + 1);
    }

    uint8_t action = ActionNameToFlag(name);
    if (action == 0) {
        SetErr(errbuf, errbuflen, "unknown action '%s'", name);
        return -1;
    }
    *action_out = action;
    *scope_out = colon ? ScopeNameToFlag(scope) : (uint8_t)ACTION_SCOPE_AUTO;
    return 0;
}

/* -------------------------------------------------------------------------
 * Decision-hook token parsing
 * ------------------------------------------------------------------------- */

/** \brief Parse the `<proto:state` operator token.
 *
 *  The leading '<' has already been confirmed by the classifier. We strip
 *  it, split on the first ':', and bounds-check each half against the
 *  PriorStateRule struct's inline char arrays.
 */
static int ParseHookToken(const char *tok, PriorStateRule *out, char *errbuf, size_t errbuflen)
{
    if (tok[0] != '<') {
        SetErr(errbuf, errbuflen, "expected '<proto:state' hook token, got '%s'", tok);
        return -1;
    }
    const char *body = tok + 1;
    const char *colon = strchr(body, ':');
    if (colon == NULL) {
        SetErr(errbuf, errbuflen, "malformed hook token '%s': missing ':' between proto and state",
                tok);
        return -1;
    }
    size_t proto_len = (size_t)(colon - body);
    size_t state_len = strlen(colon + 1);
    if (proto_len == 0) {
        SetErr(errbuf, errbuflen, "malformed hook token '%s': empty proto", tok);
        return -1;
    }
    if (state_len == 0) {
        SetErr(errbuf, errbuflen, "malformed hook token '%s': empty state", tok);
        return -1;
    }
    if (proto_len >= sizeof(out->proto)) {
        SetErr(errbuf, errbuflen, "proto name '%.*s' too long (max %zu chars)", (int)proto_len,
                body, sizeof(out->proto) - 1);
        return -1;
    }
    if (state_len >= sizeof(out->state)) {
        SetErr(errbuf, errbuflen, "state name '%s' too long (max %zu chars)", colon + 1,
                sizeof(out->state) - 1);
        return -1;
    }
    memcpy(out->proto, body, proto_len);
    out->proto[proto_len] = '\0';
    memcpy(out->state, colon + 1, state_len);
    out->state[state_len] = '\0';
    return 0;
}

/* -------------------------------------------------------------------------
 * Options parsing
 * ------------------------------------------------------------------------- */

/** \brief Append an option-block chunk (keyword plus trailing "; ") to the
 *         growing \p *remainder buffer, growing it as necessary.
 */
static int RemainderAppend(char **remainder, size_t *len, size_t *cap, const char *opt,
        size_t opt_len)
{
    /* Two extra bytes for "; " plus one for NUL. */
    size_t needed = *len + opt_len + 3;
    if (needed > *cap) {
        size_t new_cap = (*cap == 0) ? 64 : (*cap * 2);
        while (new_cap < needed) {
            new_cap *= 2;
        }
        char *np = SCRealloc(*remainder, new_cap);
        if (np == NULL) {
            return -1;
        }
        *remainder = np;
        *cap = new_cap;
    }
    memcpy(*remainder + *len, opt, opt_len);
    *len += opt_len;
    (*remainder)[(*len)++] = ';';
    (*remainder)[(*len)++] = ' ';
    (*remainder)[*len] = '\0';
    return 0;
}

/** \brief Parse one uint32 option value into \p *out. */
static int ParseUint32Value(const char *val, size_t val_len, uint32_t *out, const char *keyword,
        char *errbuf, size_t errbuflen)
{
    char buf[24];
    if (val_len == 0 || val_len >= sizeof(buf)) {
        SetErr(errbuf, errbuflen, "invalid value for '%s': empty or too long", keyword);
        return -1;
    }
    memcpy(buf, val, val_len);
    buf[val_len] = '\0';
    if (ByteExtractStringUint32(out, 10, 0, buf) <= 0) {
        SetErr(errbuf, errbuflen, "invalid numeric value for '%s': '%s'", keyword, buf);
        return -1;
    }
    return 0;
}

/** \brief Parse the options block between '(' and ')'.
 *
 *  Tokenises on ';' respecting `"..."` quoting (so a `content:"a;b"` is
 *  kept intact) and escaped semicolons (`\;`). Extracts sid/gid/rev/msg;
 *  everything else is preserved verbatim in \p out->options_remainder so
 *  the expander can re-emit it in the Decision_Hook rule without
 *  interpretation.
 *
 *  The options_remainder output format is a sequence of
 *  `<keyword>[:<value>]; ` chunks (each keyword is followed by a
 *  semicolon and a single space) so the expander can splice in
 *  `sid:N; rev:N;` after. Leading/trailing whitespace on each chunk is
 *  trimmed.
 */
static int ParseOptionsBlock(const char *opts, size_t opts_len, PriorStateRule *out, char *errbuf,
        size_t errbuflen)
{
    char *remainder = NULL;
    size_t remainder_len = 0;
    size_t remainder_cap = 0;
    bool sid_seen = false;

    const char *p = opts;
    const char *end = opts + opts_len;

    while (p < end) {
        /* Skip leading whitespace. */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        const char *opt_start = p;
        bool in_quotes = false;
        const char *opt_end = NULL;

        while (p < end) {
            char c = *p;
            if (in_quotes) {
                if (c == '"') {
                    in_quotes = false;
                }
                p++;
                continue;
            }
            if (c == '"') {
                in_quotes = true;
                p++;
                continue;
            }
            if (c == ';') {
                /* Mirror SigParseOptions: honour escaped semicolons. */
                if (p > opt_start && *(p - 1) == '\\') {
                    p++;
                    continue;
                }
                opt_end = p;
                p++; /* skip terminator */
                break;
            }
            p++;
        }

        if (opt_end == NULL) {
            /* No terminating ';' for the final chunk. Empty tail is OK
             * (e.g. a training space); a non-empty un-terminated chunk
             * is a parse error consistent with Suricata's loader. */
            while (opt_start < end && (*opt_start == ' ' || *opt_start == '\t')) {
                opt_start++;
            }
            if (opt_start < end) {
                SetErr(errbuf, errbuflen, "option not terminated with ';': '%.*s'",
                        (int)(end - opt_start), opt_start);
                goto error;
            }
            break;
        }

        size_t opt_len = (size_t)(opt_end - opt_start);
        /* Trim trailing whitespace inside the option. */
        while (opt_len > 0 && (opt_start[opt_len - 1] == ' ' || opt_start[opt_len - 1] == '\t')) {
            opt_len--;
        }
        if (opt_len == 0) {
            continue;
        }

        /* Split name:value on the first unquoted ':'. */
        const char *colon = NULL;
        bool iq = false;
        for (size_t i = 0; i < opt_len; i++) {
            char c = opt_start[i];
            if (iq) {
                if (c == '"') {
                    iq = false;
                }
                continue;
            }
            if (c == '"') {
                iq = true;
                continue;
            }
            if (c == ':') {
                colon = opt_start + i;
                break;
            }
        }

        size_t name_len = colon ? (size_t)(colon - opt_start) : opt_len;
        while (name_len > 0 &&
                (opt_start[name_len - 1] == ' ' || opt_start[name_len - 1] == '\t')) {
            name_len--;
        }

        char name[64];
        if (name_len == 0 || name_len >= sizeof(name)) {
            SetErr(errbuf, errbuflen, "invalid option: name empty or too long in '%.*s'",
                    (int)opt_len, opt_start);
            goto error;
        }
        memcpy(name, opt_start, name_len);
        name[name_len] = '\0';

        const char *val = NULL;
        size_t val_len = 0;
        if (colon) {
            val = colon + 1;
            while (val < opt_start + opt_len && (*val == ' ' || *val == '\t')) {
                val++;
            }
            val_len = (size_t)((opt_start + opt_len) - val);
        }

        if (strcasecmp(name, "sid") == 0) {
            if (!colon) {
                SetErr(errbuf, errbuflen, "'sid' option requires a value");
                goto error;
            }
            if (ParseUint32Value(val, val_len, &out->sid, "sid", errbuf, errbuflen) < 0) {
                goto error;
            }
            sid_seen = true;
        } else if (strcasecmp(name, "gid") == 0) {
            if (!colon) {
                SetErr(errbuf, errbuflen, "'gid' option requires a value");
                goto error;
            }
            if (ParseUint32Value(val, val_len, &out->gid, "gid", errbuf, errbuflen) < 0) {
                goto error;
            }
        } else if (strcasecmp(name, "rev") == 0) {
            if (!colon) {
                SetErr(errbuf, errbuflen, "'rev' option requires a value");
                goto error;
            }
            if (ParseUint32Value(val, val_len, &out->rev, "rev", errbuf, errbuflen) < 0) {
                goto error;
            }
        } else if (strcasecmp(name, "msg") == 0) {
            if (!colon || val_len == 0) {
                SetErr(errbuf, errbuflen, "'msg' option requires a quoted value");
                goto error;
            }
            /* Strip surrounding double-quotes if present, matching how
             * Suricata's option parser renders msg values. */
            const char *mval = val;
            size_t mlen = val_len;
            if (mlen >= 2 && mval[0] == '"' && mval[mlen - 1] == '"') {
                mval++;
                mlen -= 2;
            }
            char *msg = SCMalloc(mlen + 1);
            if (msg == NULL) {
                SetErr(errbuf, errbuflen, "out of memory parsing msg");
                goto error;
            }
            memcpy(msg, mval, mlen);
            msg[mlen] = '\0';
            SCFree(out->msg);
            out->msg = msg;
        } else {
            /* Preserve verbatim for the expander. */
            if (RemainderAppend(&remainder, &remainder_len, &remainder_cap, opt_start, opt_len) <
                    0) {
                SetErr(errbuf, errbuflen, "out of memory building options_remainder");
                goto error;
            }
        }
    }

    if (!sid_seen) {
        SetErr(errbuf, errbuflen, "missing required 'sid' option");
        goto error;
    }

    if (remainder_len > 0) {
        /* Drop the trailing ' ' so the expander can append "sid:N;" with
         * a preceding space consistently. Keep the final ';'. */
        if (remainder_len >= 1 && remainder[remainder_len - 1] == ' ') {
            remainder[--remainder_len] = '\0';
        }
        out->options_remainder = remainder;
    } else {
        SCFree(remainder);
    }
    return 0;

error:
    SCFree(remainder);
    return -1;
}

/* -------------------------------------------------------------------------
 * Public entry points
 * ------------------------------------------------------------------------- */

void PriorStateRuleClean(PriorStateRule *r)
{
    if (r == NULL) {
        return;
    }
    SCFree(r->src_addr);
    SCFree(r->src_port);
    SCFree(r->dst_addr);
    SCFree(r->dst_port);
    SCFree(r->direction_op);
    SCFree(r->msg);
    SCFree(r->options_remainder);
    memset(r, 0, sizeof(*r));
}

int PriorStateParseRule(const char *line, const char *file, int lineno, PriorStateRule *out,
        char *errbuf, size_t errbuflen)
{
    if (line == NULL || out == NULL) {
        SetErr(errbuf, errbuflen, "NULL input to PriorStateParseRule");
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->file = file;
    out->lineno = lineno;
    out->form = PRIOR_STATE_OPERATOR;
    out->gid = 1;
    out->rev = 1;

    /* Locate the options block: the first unquoted '(' ... matching ')'.
     * The header runs from the first non-whitespace byte of the line up
     * to the '('; everything inside '(' and ')' is the options block. */
    const char *p = line;
    SkipWs(&p);

    const char *opts_start = NULL;
    {
        bool in_quotes = false;
        for (const char *q = p; *q != '\0'; q++) {
            if (in_quotes) {
                if (*q == '"') {
                    in_quotes = false;
                }
                continue;
            }
            if (*q == '"') {
                in_quotes = true;
                continue;
            }
            if (*q == '(') {
                opts_start = q + 1;
                break;
            }
        }
    }
    if (opts_start == NULL) {
        SetErr(errbuf, errbuflen, "rule has no options block ('(' not found)");
        return -1;
    }

    /* Find the matching ')' — we trim trailing whitespace and then
     * expect the last non-whitespace byte of the line to be ')'. */
    const char *line_end = line + strlen(line);
    while (line_end > opts_start && (line_end[-1] == '\n' || line_end[-1] == '\r' ||
                                            line_end[-1] == ' ' || line_end[-1] == '\t')) {
        line_end--;
    }
    if (line_end == opts_start || line_end[-1] != ')') {
        SetErr(errbuf, errbuflen, "rule options block not terminated with ')'");
        return -1;
    }
    const char *opts_end = line_end - 1; /* points AT the ')' byte */

    /* Copy the header (from p up to and including whitespace before '(' )
     * into a mutable buffer and tokenise. The header excludes the '('. */
    size_t hlen = (size_t)((opts_start - 1) - p);
    char *hbuf = SCMalloc(hlen + 1);
    if (hbuf == NULL) {
        SetErr(errbuf, errbuflen, "out of memory");
        goto error;
    }
    memcpy(hbuf, p, hlen);
    hbuf[hlen] = '\0';

    /* Seven tokens, in order: action, hook, src, sport, dir, dst, dport. */
    char action_tok[48];
    char hook_tok[96]; /* "<" + proto(16) + ":" + state(64) + margin */
    char src_tok[1024];
    char sp_tok[1024];
    char dir_tok[8];
    char dst_tok[1024];
    char dp_tok[1024];

    const char *hp = hbuf;
    if (NextHeaderToken(&hp, action_tok, sizeof(action_tok)) < 0) {
        SetErr(errbuf, errbuflen, "rule header missing action token");
        SCFree(hbuf);
        goto error;
    }
    if (NextHeaderToken(&hp, hook_tok, sizeof(hook_tok)) < 0) {
        SetErr(errbuf, errbuflen, "rule header missing '<proto:state' token");
        SCFree(hbuf);
        goto error;
    }
    if (NextHeaderToken(&hp, src_tok, sizeof(src_tok)) < 0) {
        SetErr(errbuf, errbuflen, "rule header missing source address");
        SCFree(hbuf);
        goto error;
    }
    if (NextHeaderToken(&hp, sp_tok, sizeof(sp_tok)) < 0) {
        SetErr(errbuf, errbuflen, "rule header missing source port");
        SCFree(hbuf);
        goto error;
    }
    if (NextHeaderToken(&hp, dir_tok, sizeof(dir_tok)) < 0) {
        SetErr(errbuf, errbuflen, "rule header missing direction operator");
        SCFree(hbuf);
        goto error;
    }
    if (NextHeaderToken(&hp, dst_tok, sizeof(dst_tok)) < 0) {
        SetErr(errbuf, errbuflen, "rule header missing destination address");
        SCFree(hbuf);
        goto error;
    }
    if (NextHeaderToken(&hp, dp_tok, sizeof(dp_tok)) < 0) {
        SetErr(errbuf, errbuflen, "rule header missing destination port");
        SCFree(hbuf);
        goto error;
    }
    /* Reject trailing garbage between the last port and the '('. */
    SkipWs(&hp);
    if (*hp != '\0') {
        SetErr(errbuf, errbuflen, "trailing garbage in rule header before '(': '%s'", hp);
        SCFree(hbuf);
        goto error;
    }
    SCFree(hbuf);

    /* Validate direction operator. The expander only knows how to emit
     * the two directions Suricata's parser accepts. */
    if (strcmp(dir_tok, "->") != 0 && strcmp(dir_tok, "<>") != 0) {
        SetErr(errbuf, errbuflen,
                "invalid direction operator '%s' (expected '->' or '<>')", dir_tok);
        goto error;
    }

    /* Parse the action token. */
    if (ParseActionToken(action_tok, &out->action, &out->action_scope, errbuf, errbuflen) < 0) {
        goto error;
    }

    /* Parse the operator-form hook token. */
    if (ParseHookToken(hook_tok, out, errbuf, errbuflen) < 0) {
        goto error;
    }

    /* Resolve the app-layer protocol. The validator (Phase 2 task 4)
     * produces PSV_UNKNOWN_PROTO if alproto is ALPROTO_UNKNOWN; we keep
     * going here so the validator gets to run and emit the structured
     * error rather than aborting with a generic parse error. */
    out->alproto = AppLayerGetProtoByName(out->proto);

    /* Populate the full transport set for the decision protocol. The
     * expander's Step 2 iterates every registered transport (TLS →
     * {TCP}, SNMP → {UDP}, DNS → {TCP, UDP}) so a single
     * Prior_State_Rule permits the flow regardless of which transport
     * the traffic actually arrives on (Req 1.3, 1.5).
     *
     * On unknown alproto the registry returns <0; we leave the array
     * zero-initialised and count == 0 so Step 2 emits nothing — the
     * validator will then reject the rule with PSV_UNKNOWN_PROTO and
     * the expander never runs. */
    const int max_ipprotos =
            (int)(sizeof(out->transport_ipprotos) / sizeof(out->transport_ipprotos[0]));
    const int n_ipprotos = StateMachineRegistryGetSupportedTransports(
            out->alproto, out->transport_ipprotos, max_ipprotos);
    if (n_ipprotos < 0) {
        out->transport_ipprotos_count = 0;
        memset(out->transport_ipprotos, 0, sizeof(out->transport_ipprotos));
    } else {
        out->transport_ipprotos_count = n_ipprotos;
    }

    /* Copy the five-tuple strings verbatim. */
    out->src_addr = SCStrdup(src_tok);
    out->src_port = SCStrdup(sp_tok);
    out->dst_addr = SCStrdup(dst_tok);
    out->dst_port = SCStrdup(dp_tok);
    out->direction_op = SCStrdup(dir_tok);
    if (out->src_addr == NULL || out->src_port == NULL || out->dst_addr == NULL ||
            out->dst_port == NULL || out->direction_op == NULL) {
        SetErr(errbuf, errbuflen, "out of memory storing five-tuple");
        goto error;
    }

    /* Parse options. */
    size_t opts_len = (size_t)(opts_end - opts_start);
    if (ParseOptionsBlock(opts_start, opts_len, out, errbuf, errbuflen) < 0) {
        goto error;
    }

    return 0;

error:
    PriorStateRuleClean(out);
    return -1;
}

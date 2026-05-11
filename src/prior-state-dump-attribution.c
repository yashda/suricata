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
 * \brief Scratch attribution-table implementation. See the header for
 *        the contract and the POC scope boundary. The implementation is
 *        intentionally simple — a small open-addressing hash on uint32_t
 *        runtime SIDs — because the table is only populated during a
 *        `--dump-expanded-rules` run and lives for the duration of that
 *        single-shot rule-load pass.
 */

#include "suricata-common.h"
#include "prior-state-dump-attribution.h"

#include "util-debug.h"
#include "util-mem.h"

/* -------------------------------------------------------------------------
 * Internal storage
 * -------------------------------------------------------------------------
 *
 * A flat dynamic array holds PriorStateDumpAttribution records. The dump
 * walker iterates the signature list exactly once and does one lookup
 * per Signature, so an O(N) linear scan would already be acceptable; we
 * use an open-addressing hash keyed by runtime SID because expansions
 * can produce hundreds of SIDs per rule file and keeping lookups O(1)
 * leaves headroom for the full fixture set in task 8.
 */

typedef struct Entry_ {
    uint32_t sid;                  /**< 0 = empty slot; runtime SID is never 0 */
    PriorStateDumpAttribution rec;
} Entry;

static bool g_enabled = false;
static Entry *g_entries = NULL;
static size_t g_capacity = 0; /**< power of two; 0 == table not allocated */
static size_t g_count = 0;    /**< number of occupied entries */
static uint32_t g_next_load_seq = 1; /**< monotonically increasing load-order
                                      *   counter assigned to every recorded
                                      *   attribution. Reset on Enable(). */

#define PRIOR_STATE_DUMP_ATTR_INIT_CAP 64

static void FreeEntry(Entry *e)
{
    if (e == NULL) {
        return;
    }
    SCFree(e->rec.label);
    SCFree(e->rec.decision_hook);
    SCFree(e->rec.src_file);
    memset(e, 0, sizeof(*e));
}

static void FreeAll(void)
{
    if (g_entries == NULL) {
        return;
    }
    for (size_t i = 0; i < g_capacity; i++) {
        if (g_entries[i].sid != 0) {
            FreeEntry(&g_entries[i]);
        }
    }
    SCFree(g_entries);
    g_entries = NULL;
    g_capacity = 0;
    g_count = 0;
}

/* Fowler-Noll-Vo finalization style mix used for hashing uint32_t keys —
 * cheap and good enough for this short-lived table. */
static size_t HashSid(uint32_t sid, size_t capacity)
{
    uint32_t h = sid;
    h ^= h >> 16;
    h *= 0x7feb352dU;
    h ^= h >> 15;
    h *= 0x846ca68bU;
    h ^= h >> 16;
    return (size_t)h & (capacity - 1);
}

static int Resize(size_t new_cap)
{
    Entry *old = g_entries;
    size_t old_cap = g_capacity;

    Entry *ne = SCCalloc(new_cap, sizeof(Entry));
    if (ne == NULL) {
        return -1;
    }
    g_entries = ne;
    g_capacity = new_cap;
    g_count = 0;

    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].sid == 0) {
            continue;
        }
        /* Re-insert (move, no deep copy). */
        size_t idx = HashSid(old[i].sid, new_cap);
        while (g_entries[idx].sid != 0) {
            idx = (idx + 1) & (new_cap - 1);
        }
        g_entries[idx] = old[i];
        g_count++;
    }
    SCFree(old);
    return 0;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

void PriorStateDumpAttributionEnable(void)
{
    FreeAll();
    g_entries = SCCalloc(PRIOR_STATE_DUMP_ATTR_INIT_CAP, sizeof(Entry));
    if (g_entries == NULL) {
        /* OOM at enable time: leave the flag off so Record() stays a no-op.
         * The dump walker will render bare rules (no attribution comments);
         * the caller can still proceed instead of failing the whole pass. */
        SCLogError(
                "fw: --dump-expanded-rules: out of memory allocating attribution table; "
                "attribution comments will be omitted");
        g_enabled = false;
        return;
    }
    g_capacity = PRIOR_STATE_DUMP_ATTR_INIT_CAP;
    g_count = 0;
    g_next_load_seq = 1;
    g_enabled = true;
}

void PriorStateDumpAttributionDisable(void)
{
    g_enabled = false;
    FreeAll();
}

bool PriorStateDumpAttributionIsEnabled(void)
{
    return g_enabled;
}

void PriorStateDumpAttributionRecord(uint32_t runtime_sid, uint32_t parent_sid,
        uint16_t sub_index, const char *label, const char *decision_hook, const char *file,
        int lineno)
{
    if (!g_enabled) {
        return;
    }
    if (runtime_sid == 0) {
        /* Sentinel collision — runtime SIDs on valid Signatures are
         * always non-zero. Silently ignore. */
        return;
    }
    if (g_entries == NULL || g_capacity == 0) {
        return;
    }

    /* Grow when load factor exceeds ~0.7. */
    if ((g_count + 1) * 10 > g_capacity * 7) {
        if (Resize(g_capacity * 2) < 0) {
            SCLogError("fw: --dump-expanded-rules: out of memory growing attribution table");
            return;
        }
    }

    size_t idx = HashSid(runtime_sid, g_capacity);
    while (g_entries[idx].sid != 0) {
        if (g_entries[idx].sid == runtime_sid) {
            /* Collision on the same SID — expanders must never emit
             * duplicate runtime SIDs within a single rule, but a
             * subsequent rule file could legitimately reuse a SID the
             * user authored in a hand-written rule (the collision
             * check for that is Phase 2 task 12). Replace the record
             * so the dump walker shows the most-recently-loaded
             * attribution, matching legacy DetectFirewallRuleAppendNew
             * dup-sig semantics. */
            FreeEntry(&g_entries[idx]);
            g_count--;
            break;
        }
        idx = (idx + 1) & (g_capacity - 1);
    }

    char *label_dup = SCStrdup(label != NULL ? label : "");
    char *hook_dup = NULL;
    if (decision_hook != NULL) {
        hook_dup = SCStrdup(decision_hook);
    }
    char *file_dup = SCStrdup(file != NULL ? file : "");

    if (label_dup == NULL || file_dup == NULL || (decision_hook != NULL && hook_dup == NULL)) {
        SCFree(label_dup);
        SCFree(hook_dup);
        SCFree(file_dup);
        SCLogError("fw: --dump-expanded-rules: out of memory recording attribution for sid %u",
                runtime_sid);
        return;
    }

    g_entries[idx].sid = runtime_sid;
    g_entries[idx].rec.parent_sid = parent_sid;
    g_entries[idx].rec.sub_index = sub_index;
    g_entries[idx].rec.is_decision_hook = (sub_index == 0);
    g_entries[idx].rec.load_seq = g_next_load_seq++;
    g_entries[idx].rec.label = label_dup;
    g_entries[idx].rec.decision_hook = hook_dup;
    g_entries[idx].rec.src_file = file_dup;
    g_entries[idx].rec.src_lineno = lineno;
    g_count++;
}

const PriorStateDumpAttribution *PriorStateDumpAttributionLookup(uint32_t runtime_sid)
{
    if (!g_enabled || g_entries == NULL || g_capacity == 0 || runtime_sid == 0) {
        return NULL;
    }
    size_t idx = HashSid(runtime_sid, g_capacity);
    /* Probe until we hit the requested SID or an empty slot. */
    for (size_t probes = 0; probes < g_capacity; probes++) {
        if (g_entries[idx].sid == 0) {
            return NULL;
        }
        if (g_entries[idx].sid == runtime_sid) {
            return &g_entries[idx].rec;
        }
        idx = (idx + 1) & (g_capacity - 1);
    }
    return NULL;
}

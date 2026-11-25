/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_audit.h - emit io_uring activity as records the existing audit/IDS
 * pipeline already ingests.
 *
 * TWO OUTPUT FORMATS, ONE EVENT
 * -----------------------------
 *  1. Linux audit native (AUDIT_URINGOP).  Linux >= 6.0 has an io_uring audit
 *     record type (AUDIT_URINGOP, 1336) and a matching rule filter
 *     (AUDIT_FILTER_URING_EXIT).  But upstream only emits it from io_issue_sqe()
 *     for opcodes whose io_issue_def lacks .audit_skip -- which is precisely
 *     NOT the 28 file/network/stat opcodes we care about.  We emit the same
 *     record *shape* for every opcode, filling in the fields the kernel's own
 *     audit_log_uring() would have used (uring_op, success, exit, items, uid
 *     family, task context) plus the reconstructed syscall equivalence, so an
 *     existing auditd rule on AUDIT_URINGOP or on the syscall name keeps
 *     working.
 *
 *  2. JSON lines.  A stable, self-describing record for SIEMs and for the
 *     portable (non-Linux) test build.  It carries the identity captured at
 *     *submit* time, which is the crux: the kernel executes the operation on a
 *     worker thread some time later, so by completion time `current` is the
 *     worker and attribution is gone.  We record `pid/tgid/uid/euid` of the
 *     submitter, the ring id, and both timestamps, so the completion can be
 *     tied back to whoever queued it.
 *
 * DESIGNED TO BE SAFE ON THE HOT PATH
 * -----------------------------------
 * Formatting allocates nothing per record (caller owns a threaded buffer) and
 * writes no user pointers as bare values without marking them, so the output
 * can be parsed without a second parser.  It never dereferences a userspace
 * pointer.
 */
#ifndef IOU_AUDIT_H
#define IOU_AUDIT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "iou_op.h"
#include "iou_rules.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	IOU_FMT_JSONL = 0,     /* one JSON object per line                    */
	IOU_FMT_AUDIT = 1,     /* Linux auditd-compatible record              */
} iou_audit_format_t;

/* Portable audit serial number: ms since boot-ish epoch + host id + seq.
 * We generate it ourselves rather than call audit_* so the same emitter works
 * in a kernel module, a userspace daemon, and a test binary. */
typedef struct iou_audit_ctx {
	FILE *out;
	iou_audit_format_t fmt;
	uint64_t epoch_ms;         /* logical clock supplied by the caller      */
	uint64_t next_seq;
	uint32_t host_id;          /* audit-style 32-bit host identifier        */
	uint32_t lost_events;      /* records dropped because the sink was full */
} iou_audit_ctx_t;

bool iou_audit_init(iou_audit_ctx_t *ac, FILE *out, iou_audit_format_t fmt,
		    uint64_t epoch_ms, uint32_t host_id);

/* Emit one event with its verdict.  `resolved_path1/2` may be NULL.  Returns
 * false if the record could not be written (full sink, I/O error); the caller
 * must treat that as "audit is blind" and act accordingly (see keeper). */
bool iou_audit_emit(iou_audit_ctx_t *ac, const iou_event_t *ev,
		    const iou_match_t *match,
		    const char *resolved_path1, const char *resolved_path2);

/* For the native audit format: the numeric "uring_op" the kernel's own
 * audit_log_uring() would print.  Exposed because the mapping (opcode number)
 * is stable and parts of the ruleset key on it. */
#define IOU_AUDIT_URINGOP 1336
/* Ambient/aux record types an IDS may already consume. */
#define IOU_AUDIT_SYSCALL 1300

/* ------------------------------------------------------------------ */
/* Offline path resolution                                             */
/* ------------------------------------------------------------------ */

/*
 * An SQE carries a *pointer* to a path string in the submitter's address
 * space, never the string itself.  A live hook resolves it in context; an
 * offline replay (a captured ring, a core dump) cannot.  For that case we allow
 * the capture to carry a sidecar mapping pointer -> path, which the offline
 * decoder consults.  This is what makes "replay yesterday's traffic against
 * today's rules" actually evaluate path rules instead of silently skipping
 * them.
 */
typedef struct iou_path_map_entry {
	uint64_t user_ptr;
	char    *path;      /* canonicalised by the loader                   */
} iou_path_map_entry_t;

typedef struct iou_path_map {
	iou_path_map_entry_t *entries;
	size_t n;
} iou_path_map_t;

/* Resolve `ptr` to a path, or NULL if unknown.  Never dereferences `ptr`. */
const char *iou_path_map_lookup(const iou_path_map_t *m, uint64_t ptr);

/* Load a "0xPTR<TAB>/abs/path" sidecar.  Returns 0 on success; *out owns its
 * strings and must be freed with iou_path_map_free(). */
int iou_path_map_load(const char *filename, iou_path_map_t *out);
void iou_path_map_free(iou_path_map_t *m);

#ifdef __cplusplus
}
#endif

#endif /* IOU_AUDIT_H */

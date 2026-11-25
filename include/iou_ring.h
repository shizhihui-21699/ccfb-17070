/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_ring.h - read the submission and completion queues of a live ring.
 *
 * WHY A RING READER AT ALL
 * ------------------------
 * There are two ways to see what a process submits:
 *
 *   (A) hook the kernel at submit time (kmod / BPF) - authoritative, sees the
 *       task identity, but needs a driver and cannot be deployed on a locked
 *       down kernel;
 *
 *   (B) read the ring's shared memory from outside - works on any kernel with
 *       no module, but the ring is plain user memory that the submitter can
 *       rewrite at will, so every byte is hostile.
 *
 * This file implements (B) as a hardening-first reader.  It is the fallback
 * path and the offline/capture path; the kmod in src/kmod is (A).  Both feed
 * the same iou_event_t to the same rules engine, which is the point: policy
 * is written once.
 *
 * MEMORY MODEL
 * ------------
 * The reader never mmaps or dereferences real memory itself.  Everything goes
 * through an iou_mem_vtable_t.  Production supplies a vtable over mmap'd pages
 * (and, for a foreign process, over process_vm_readv); tests supply a vtable
 * over a heap buffer.  That is what makes this unit-testable off Linux.
 *
 * SHARED-MEMORY RACES
 * -------------------
 * The submitter owns the SQ ring and can change head/tail/flags between any
 * two reads (the kernel's own ring is the same memory from the other side).
 * The reader therefore:
 *   - never trusts tail/head as ordering (re-validates tail within
 *     [head, head+entries] using masking);
 *   - copies an SQE once into a local before decoding it, and never re-reads;
 *   - treats a tail that moves *backwards* or a head that outruns the tail as
 *     hostile (it cannot be produced by the kernel);
 *   - reports `dropped`/overflow rather than silently missing entries.
 */
#ifndef IOU_RING_H
#define IOU_RING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "iou_sqe.h"
#include "iou_op.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Abstract memory access                                              */
/* ------------------------------------------------------------------ */

typedef struct iou_mem_vtable {
	/* Read `len` bytes from the ring address space at `off` into `dst`.
	 * Return number of bytes actually available (may be < len if the mapped
	 * region ends), or -1 on hard error.  MUST NOT fault. */
	ssize_t (*read)(void *ctx, uint64_t off, void *dst, size_t len);
	/* Optional: write `len` bytes at `off`.  NULL for read-only capture. */
	ssize_t (*write)(void *ctx, uint64_t off, const void *src, size_t len);
	void *ctx;
} iou_mem_vtable_t;

/* ------------------------------------------------------------------ */
/* Geometry                                                           */
/* ------------------------------------------------------------------ */

typedef struct iou_ring_geom {
	uint32_t setup_flags;    /* IORING_SETUP_* (ioring_params.flags)      */
	uint32_t sq_entries;     /* from params.sq_entries                    */
	uint32_t cq_entries;     /* from params.cq_entries                    */
	uint32_t sq_stride;      /* 64 or 128                                 */
	uint32_t cq_stride;      /* 16 or 32                                  */
	uint64_t sq_ring_off;    /* absolute offsets in the mapped region:
				  * base + sq_off.head (SQ head word)          */
	uint64_t sq_tail_off;    /* base + sq_off.tail                         */
	uint64_t sq_dropped_off; /* base + sq_off.dropped                      */
	uint64_t sq_array_off;   /* base + sq_off.array                        */
	uint64_t sqes_off;       /* base + sq_off.user_addr                    */
	uint64_t cq_ring_off;    /* base + cq_off.head (CQ head word)          */
	uint64_t cq_tail_off;    /* base + cq_off.tail                         */
	uint64_t cqes_off;       /* base + cq_off.cqes                         */
	uint64_t cq_overflow_off;/* base + cq_off.overflow                     */
	struct iou_sqring_offsets sq_off;
	struct iou_cqring_offsets cq_off;
} iou_ring_geom_t;

typedef struct iou_ring {
	iou_ring_geom_t geom;
	iou_mem_vtable_t mem;
	/* Our consumer cursor: the tail value we have already reported up to.
	 * This is NOT the kernel's head; head is advanced by the kernel and can
	 * outrun us, in which case we lost visibility of those entries. */
	uint32_t last_sq_tail;
	uint32_t last_cq_tail;
	uint64_t ring_id;
	uint32_t dropped_seen;   /* cumulative SQ dropped counter              */
	uint32_t overflow_seen;  /* cumulative CQ overflow counter             */
	uint32_t missed_submissions; /* entries consumed by kernel before we read */
	uint32_t missed_completions; /* entries reaped before we read             */
	uint32_t anomalies;      /* flags that should be alerted                */
} iou_ring_t;

/* Build geometry from a struct io_uring_params (as returned by io_uring_setup
 * or read from /proc/<pid>/fdinfo for a foreign ring).  `base` is the offset
 * of the mapped region that `mem` addresses (0 for a fresh mmap).
 * When `single_mmap` is true (IORING_FEAT_SINGLE_MMAP), CQ and SQ share one
 * mapping and cq offsets are relative to the same base.  Returns false on
 * impossible geometry (a hostile or corrupt params). */
bool iou_ring_geom_init(iou_ring_geom_t *g, const struct iou_params *p,
			uint64_t base, bool single_mmap);

/* Finish construction with a vtable.  `ring_id` is an externally derived
 * opaque identifier (e.g. hash of the owning ctx + creation time). */
void iou_ring_init(iou_ring_t *r, const iou_ring_geom_t *g,
		   const iou_mem_vtable_t *mem, uint64_t ring_id);

/* ------------------------------------------------------------------ */
/* Polling                                                            */
/* ------------------------------------------------------------------ */

typedef int (*iou_sqe_cb)(void *ctx, const struct iou_sqe *sqe,
			  uint32_t sq_index, uint32_t array_slot);
typedef int (*iou_cqe_cb)(void *ctx, const struct iou_cqe *cqe, uint32_t cq_index);

/* Consume all submissions currently queued and hand each raw SQE to `cb`
 * (already copied out of the shared ring; `sqe` is a private copy, `stride`
 * bytes).  Does NOT advance the shared head -- the component is a passive
 * observer, and the kernel advances head itself when the app calls
 * io_uring_enter().  Our own cursor (last_sq_head) tracks what *we* have
 * already reported, so the same SQE is not emitted twice.
 *
 * `dropped_out` (may be NULL) receives the SQ ring's dropped counter delta.
 * Returns the number of submissions delivered, or -1 on a hard read error.
 */
int iou_ring_poll_submissions(iou_ring_t *r, iou_sqe_cb cb, void *ctx,
			      uint32_t *dropped_out);

/* Consume pending completions.  Same contract as submissions: the CQE and its
 * index are delivered read-only, and our cursor advances so duplicates are not
 * re-reported.  `overflow_out` receives the CQ overflow counter. */
int iou_ring_poll_completions(iou_ring_t *r, iou_cqe_cb cb, void *ctx,
			      uint32_t *overflow_out);

/* Flag bits exposed for alerting. */
#define IOU_RING_ANOM_TAIL_BACKWARD   (1u << 0)
#define IOU_RING_ANOM_HEAD_AHEAD      (1u << 1)
#define IOU_RING_ANOM_BAD_ARRAY_SLOT  (1u << 2)
#define IOU_RING_ANOM_DROPPED         (1u << 3)
#define IOU_RING_ANOM_OVERFLOW        (1u << 4)
#define IOU_RING_ANOM_BAD_SQE_SLOT    (1u << 5)
#define IOU_RING_ANOM_CQ_REGRESS      (1u << 6)
#define IOU_RING_ANOM_MISSED          (1u << 7)

#ifdef __cplusplus
}
#endif

#endif /* IOU_RING_H */

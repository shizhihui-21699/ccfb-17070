/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_ring.c - hostile-input reader for io_uring SQ/CQ shared memory.
 *
 * Every pointer and index below comes from memory the submitter controls.
 * The rules this file follows, and why:
 *
 *  1. All accesses go through the vtable, and the vtable's read() reports how
 *     many bytes were actually available.  A short read is a hostile or
 *     truncated mapping, not a crash.
 *
 *  2. Indices are validated against the ring's own declared entry count in
 *     mask arithmetic, never used as a raw offset.  An attacker who sets
 *     sq_array[k] to 0xffffffff gets a "bad array slot" anomaly, not an
 *     out-of-bounds SQE read.
 *
 *  3. head, tail and our own cursor are read/computed once per poll and then
 *     treated as immutable.  The kernel is the only writer of head; the app is
 *     the only writer of tail.  Any triple that is not monotone in mask space
 *     is reported, never spun on.
 *
 *  4. We never write to the ring.  Advancing head would tell the app "already
 *     done" and break it; this is a passive observer.
 *
 *  5. Entries below head are unreadable: the kernel already consumed them and
 *     the app may reuse the SQE slot.  We count them as missed (an alert
 *     condition) rather than racing for them.
 */
#include <string.h>

#include "iou_ring.h"

/* Upper bound on entries we iterate in one poll, so a hostile tail cannot
 * spin us for a whole ring's worth of stale slots in one call.  The kernel
 * itself caps entries at IORING_MAX_ENTRIES. */
#define IOU_POLL_CHUNK_MAX 4096u

static bool read_u32(iou_ring_t *r, uint64_t off, uint32_t *out)
{
	ssize_t n = r->mem.read(r->mem.ctx, off, out, sizeof(*out));

	return n == (ssize_t)sizeof(*out);
}

bool iou_ring_geom_init(iou_ring_geom_t *g, const struct iou_params *p,
			uint64_t base, bool single_mmap)
{
	if (g == NULL || p == NULL)
		return false;
	memset(g, 0, sizeof(*g));

	/*
	 * The kernel rounds sq_entries up to a power of two; params carry the
	 * post-setup values.  We sanity-check instead of re-deriving: every
	 * out-of-range use is caught by masking anyway, so these checks only
	 * reject geometry that cannot be real.
	 *
	 * NOTE: sq_off.ring_mask / ring_entries / array are *offsets into the
	 * mmap region*, not values.  The mask value itself must be read from
	 * memory at sq_off.ring_mask (the reader does this); here we may only
	 * validate sq_entries, which is a genuine count.
	 */
	if (p->sq_entries == 0 || p->sq_entries > IOU_MAX_ENTRIES)
		return false;
	if (p->sq_entries & (p->sq_entries - 1u))
		return false;   /* must be a power of two */
	if (p->cq_entries == 0 || p->cq_entries > IOU_MAX_CQ_ENTRIES)
		return false;

	g->setup_flags = p->flags;
	g->sq_entries = p->sq_entries;
	g->cq_entries = p->cq_entries;
	g->sq_stride = iou_sqe_stride(p->flags);
	g->cq_stride = iou_cqe_stride(p->flags);
	g->sq_off = p->sq_off;
	g->cq_off = p->cq_off;

	/* The offsets in params are relative to the mmap base.  For a
	 * SINGLE_MMAP ring, sq and cq rings live in the same mapping; otherwise
	 * the caller combines two mappings into one coherent `mem` view.  We
	 * record absolute offsets so the reader is mapping-agnostic. */
	g->sq_ring_off = base + p->sq_off.head;
	g->sq_tail_off = base + p->sq_off.tail;
	g->sq_dropped_off = base + p->sq_off.dropped;
	g->sq_array_off = base + p->sq_off.array;
	g->sqes_off = base + p->sq_off.user_addr;
	/*
	 * Every offset in sq_off/cq_off is *relative to the mmap base*, not to
	 * each other.  Store them all as absolute so a reader never adds one
	 * offset that already contains another (the double-count bug that makes
	 * the CQEs appear one ring-header further along than they are).
	 */
	g->cq_ring_off = base + p->cq_off.head;
	g->cq_tail_off = base + p->cq_off.tail;
	g->cqes_off = base + p->cq_off.cqes;
	g->cq_overflow_off = base + p->cq_off.overflow;
	(void)single_mmap;
	return true;
}

void iou_ring_init(iou_ring_t *r, const iou_ring_geom_t *g,
		   const iou_mem_vtable_t *mem, uint64_t ring_id)
{
	memset(r, 0, sizeof(*r));
	r->geom = *g;
	r->mem = *mem;
	r->ring_id = ring_id;
}

/* ------------------------------------------------------------------ */
/* Submissions                                                         */
/* ------------------------------------------------------------------ */

int iou_ring_poll_submissions(iou_ring_t *r, iou_sqe_cb cb, void *ctx,
			      uint32_t *dropped_out)
{
	uint32_t head, tail, mask, dropped = 0;
	uint32_t start, end, idx;
	uint32_t delivered = 0;
	uint8_t sqe_copy[IOU_SQE128_SIZE];

	if (r == NULL || cb == NULL)
		return -1;

	mask = r->geom.sq_entries - 1u;   /* entries is validated power-of-two */
	if (!read_u32(r, r->geom.sq_ring_off, &head))
		return -1;
	if (!read_u32(r, r->geom.sq_tail_off, &tail))
		return -1;

	/*
	 * Cursor arithmetic.  last_sq_tail . head . tail must be a monotone
	 * triple in mask space.  We clamp forward in either direction and record
	 * an anomaly; we never wrap-spin.
	 */
	start = r->last_sq_tail;

	if ((int32_t)(tail - start) < 0) {
		/* Tail regressed below our cursor.  The shared tail is app-owned
		 * and the app can (in principle) hand us a stale value; treat it as
		 * a reset and re-baseline on the current tail. */
		r->anomalies |= IOU_RING_ANOM_TAIL_BACKWARD;
		start = tail;
	}
	if (tail - start > r->geom.sq_entries) {
		/* Producer out-ran us by more than a full ring between polls. */
		r->anomalies |= IOU_RING_ANOM_TAIL_BACKWARD;
		start = tail - r->geom.sq_entries;
	}
	if ((int32_t)(head - start) > 0) {
		/* Entries at [start, head) were already consumed by the kernel; the
		 * app may be reusing those slots.  We cannot read them without a
		 * race, so count them as missed and start at head. */
		r->missed_submissions += head - start;
		r->anomalies |= IOU_RING_ANOM_MISSED;
		start = head;
	}
	if ((int32_t)(tail - start) < 0) {
		/* head is ahead of tail: only possible on a corrupt ring. */
		r->anomalies |= IOU_RING_ANOM_HEAD_AHEAD;
		r->last_sq_tail = tail;
		return 0;
	}

	end = tail;
	if (end - start > IOU_POLL_CHUNK_MAX) {
		/* Huge backlog in one poll: cap it and let the next poll finish.
		 * Record that we are behind. */
		r->anomalies |= IOU_RING_ANOM_TAIL_BACKWARD;
		end = start + IOU_POLL_CHUNK_MAX;
	}

	for (idx = start; idx < end; idx++) {
		uint32_t slot = idx & mask;      /* index into sq_array */
		uint32_t sqe_index;
		uint64_t sqe_off;
		ssize_t got;

		if (!read_u32(r, r->geom.sq_array_off + (uint64_t)slot * 4u,
			      &sqe_index)) {
			r->anomalies |= IOU_RING_ANOM_BAD_ARRAY_SLOT;
			continue;
		}
		/* The array entry is a u32 the app controls.  Anything outside
		 * [0, entries) cannot name an SQE in this ring. */
		if (sqe_index >= r->geom.sq_entries) {
			r->anomalies |= IOU_RING_ANOM_BAD_ARRAY_SLOT;
			continue;
		}

		sqe_off = r->geom.sqes_off +
			  (uint64_t)(sqe_index & mask) * r->geom.sq_stride;
		got = r->mem.read(r->mem.ctx, sqe_off, sqe_copy, r->geom.sq_stride);
		if (got != (ssize_t)r->geom.sq_stride) {
			r->anomalies |= IOU_RING_ANOM_BAD_SQE_SLOT;
			continue;
		}

		/* Private copy: decode from sqe_copy, never from the ring again. */
		cb(ctx, (const struct iou_sqe *)sqe_copy, sqe_index, slot);
		delivered++;
	}

	r->last_sq_tail = end;

	if (r->geom.sq_dropped_off != 0 &&
	    read_u32(r, r->geom.sq_dropped_off, &dropped)) {
		if (dropped != r->dropped_seen) {
			r->anomalies |= IOU_RING_ANOM_DROPPED;
			r->dropped_seen = dropped;
		}
	}
	if (dropped_out)
		*dropped_out = dropped;

	return (int)delivered;
}

/* ------------------------------------------------------------------ */
/* Completions                                                         */
/* ------------------------------------------------------------------ */

int iou_ring_poll_completions(iou_ring_t *r, iou_cqe_cb cb, void *ctx,
			      uint32_t *overflow_out)
{
	uint32_t head, tail, mask, overflow = 0;
	uint32_t start, end, idx, delivered = 0;
	uint8_t cqe_copy[IOU_CQE32_SIZE];
	ssize_t got;

	if (r == NULL || cb == NULL)
		return -1;

	mask = r->geom.cq_entries - 1u;
	if (!read_u32(r, r->geom.cq_ring_off, &head))
		return -1;
	if (!read_u32(r, r->geom.cq_tail_off, &tail))
		return -1;

	start = r->last_cq_tail;
	if ((int32_t)(tail - start) < 0) {
		r->anomalies |= IOU_RING_ANOM_CQ_REGRESS;
		start = tail;
	}
	if (tail - start > r->geom.cq_entries) {
		r->anomalies |= IOU_RING_ANOM_CQ_REGRESS;
		start = tail - r->geom.cq_entries;
	}
	if ((int32_t)(head - start) > 0) {
		r->missed_completions += head - start;
		r->anomalies |= IOU_RING_ANOM_MISSED;
		start = head;
	}
	if ((int32_t)(tail - start) < 0) {
		r->anomalies |= IOU_RING_ANOM_HEAD_AHEAD;
		r->last_cq_tail = tail;
		return 0;
	}

	end = tail;
	if (end - start > IOU_POLL_CHUNK_MAX) {
		r->anomalies |= IOU_RING_ANOM_CQ_REGRESS;
		end = start + IOU_POLL_CHUNK_MAX;
	}

	for (idx = start; idx < end; idx++) {
		uint64_t off = r->geom.cqes_off +
			       (uint64_t)(idx & mask) * r->geom.cq_stride;

		got = r->mem.read(r->mem.ctx, off, cqe_copy, r->geom.cq_stride);
		if (got != (ssize_t)r->geom.cq_stride) {
			r->anomalies |= IOU_RING_ANOM_BAD_SQE_SLOT;
			continue;
		}
		cb(ctx, (const struct iou_cqe *)cqe_copy, idx & mask);
		delivered++;
	}
	r->last_cq_tail = end;

	if (r->geom.cq_overflow_off != 0 &&
	    read_u32(r, r->geom.cq_overflow_off, &overflow)) {
		if (overflow != r->overflow_seen) {
			r->anomalies |= IOU_RING_ANOM_OVERFLOW;
			r->overflow_seen = overflow;
		}
	}
	if (overflow_out)
		*overflow_out = overflow;

	return (int)delivered;
}

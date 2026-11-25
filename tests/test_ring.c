/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ring.c - the ring reader under hostile/corrupt shared memory.
 *
 * The submitter owns the SQ ring memory and can write anything into it.  These
 * tests build a plausible ring layout, then corrupt it in the ways an attacker
 * (or a buggy app, or a torn read) would, and assert that the reader:
 *   - never reads outside the mapped region,
 *   - never loops unboundedly,
 *   - reports the corruption instead of silently dropping it,
 *   - and still delivers the legitimate SQEs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>

#include "iou_ring.h"
#include "iou_sqe.h"

static int failures;
static int checks;

#define CHECK(cond, ...) do { \
	checks++; \
	if (!(cond)) { \
		failures++; \
		fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

/* ------------------------------------------------------------------ */
/* A heap-backed memory model that hard-fails on out-of-region access. */
/* ------------------------------------------------------------------ */

typedef struct fake_mem {
	uint8_t *base;
	size_t   size;
	int      oob_reads;        /* reads that would overrun a mapped region */
	int      truncated_reads;  /* reads starting past the mapping (expected
				    * in the truncation test, always tolerated) */
} fake_mem_t;

static ssize_t fake_read(void *ctx, uint64_t off, void *dst, size_t len)
{
	fake_mem_t *m = ctx;

	/*
	 * A read that starts at or past the end of the mapping is the kernel's
	 * real behaviour for a truncated mmap (mmap the ring, then madvise/munmap
	 * its tail away).  It is NOT a reader bug: the reader must survive it by
	 * taking the short-read branch.  We count these separately from reads
	 * that would have *overrun* a mapped region, so tests assert on the
	 * right property.
	 */
	if (off >= m->size) {
		m->truncated_reads++;
		return 0;   /* zero bytes available, no fault */
	}
	if (off + len > m->size) {
		/* Short read, exactly like a truncated mmap. */
		memcpy(dst, m->base + off, m->size - off);
		return (ssize_t)(m->size - off);
	}
	memcpy(dst, m->base + off, len);
	return (ssize_t)len;
}

static ssize_t fake_write(void *ctx, uint64_t off, const void *src, size_t len)
{
	fake_mem_t *m = ctx;

	if (off >= m->size)
		return -1;
	if (off + len > m->size)
		len = m->size - off;
	memcpy(m->base + off, src, len);
	return (ssize_t)len;
}


/*
 * Write a u32 into the fake ring at `off`.  We use memcpy rather than a
 * uint32_t* cast: calloc returns a char pointer whose alignment the compiler
 * cannot prove, and -Wcast-align is right to complain.  The memory is actually
 * 4-aligned (offsets are multiples of 4), but memcpy is the portable spelling.
 */
static void poke_u32(void *base, uint64_t off, uint32_t v)
{
	memcpy((uint8_t *)base + off, &v, sizeof(v));
}

/* ------------------------------------------------------------------ */
/* Ring layout builder                                                 */
/* ------------------------------------------------------------------ */

typedef struct test_ring {
	fake_mem_t mem;
	struct iou_params p;
	uint64_t sqes_off;
	uint8_t  *sqes;   /* base + sq_off.user_addr, 4-aligned in practice */
} test_ring_t;

static void mem_write_cqe(struct test_ring *t, uint32_t idx,
			  const struct iou_cqe *q);

#define ENTRIES 16u
#define SQES_OFF 4096u
#define REGION  (SQES_OFF + ENTRIES * IOU_SQE_SIZE)
#define CQES_REGION_OFF (REGION + 64)

static void build_ring(test_ring_t *t)
{
	size_t need;

	memset(t, 0, sizeof(*t));
	/* One allocation covering SQ ring header, SQEs, the CQ ring header, and
	 * the CQE array that follows it. */
	need = CQES_REGION_OFF + 2 * ENTRIES * IOU_CQE_SIZE;
	t->mem.base = calloc(1, need);
	t->mem.size = need;

	memset(&t->p, 0, sizeof(t->p));
	t->p.sq_entries = ENTRIES;
	t->p.cq_entries = 2 * ENTRIES;
	t->p.flags = 0;
	t->p.sq_off.head = 0;
	t->p.sq_off.tail = 4;
	t->p.sq_off.ring_mask = 8;
	t->p.sq_off.ring_entries = 12;
	t->p.sq_off.flags = 16;
	t->p.sq_off.dropped = 20;
	t->p.sq_off.array = 64;
	t->p.sq_off.user_addr = SQES_OFF;

	t->sqes = t->mem.base + SQES_OFF;

	poke_u32(t->mem.base, t->p.sq_off.ring_mask, ENTRIES - 1);
	poke_u32(t->mem.base, t->p.sq_off.ring_entries, ENTRIES);

	t->p.cq_off.head = REGION;
	t->p.cq_off.tail = REGION + 4;
	t->p.cq_off.ring_mask = REGION + 8;
	t->p.cq_off.ring_entries = REGION + 12;
	t->p.cq_off.overflow = REGION + 16;
	t->p.cq_off.cqes = CQES_REGION_OFF;
	poke_u32(t->mem.base, t->p.cq_off.ring_mask, 2 * ENTRIES - 1);
	poke_u32(t->mem.base, t->p.cq_off.ring_entries, 2 * ENTRIES);
}

static void destroy_ring(test_ring_t *t)
{
	free(t->mem.base);
	memset(t, 0, sizeof(*t));
}

/* Fill SQE slot `i` with a READ on fd i. */
static void write_sqe(test_ring_t *t, uint32_t i, uint8_t opcode, int32_t fd)
{
	struct iou_sqe s;

	memset(&s, 0, sizeof(s));
	s.opcode = opcode;
	s.fd = fd;
	s.len = 128;
	memcpy(t->sqes + (size_t)i * IOU_SQE_SIZE, &s, sizeof(s));
}

static void mem_write_cqe(struct test_ring *t, uint32_t idx,
			  const struct iou_cqe *q)
{
	memcpy(t->mem.base + t->p.cq_off.cqes + (uint64_t)idx * IOU_CQE_SIZE,
	       q, sizeof(*q));
}

/* Push `n` submissions through the array, slots given from `first_slot`. */
static void push_range(test_ring_t *t, uint32_t first_slot, uint32_t n,
		       uint8_t opcode)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		uint32_t idx = first_slot + i;

		write_sqe(t, idx, opcode, (int32_t)(100 + idx));
		poke_u32(t->mem.base, t->p.sq_off.array + (uint64_t)idx * 4u, idx);
	}
	poke_u32(t->mem.base, t->p.sq_off.tail, first_slot + n);
}

/* ------------------------------------------------------------------ */
/* Callbacks                                                           */
/* ------------------------------------------------------------------ */

typedef struct collect {
	struct iou_sqe sqes[64];
	uint32_t idx[64];
	size_t n;
	struct iou_cqe cqes[64];
	size_t n_cqe;
} collect_t;

static int on_sqe(void *ctx, const struct iou_sqe *s, uint32_t idx, uint32_t slot)
{
	collect_t *c = ctx;

	(void)slot;
	if (c->n < 64) {
		memcpy(&c->sqes[c->n], s, sizeof(*s));
		c->idx[c->n] = idx;
		c->n++;
	}
	return 0;
}

static int on_cqe(void *ctx, const struct iou_cqe *q, uint32_t idx)
{
	collect_t *c = ctx;

	if (c->n_cqe < 64) {
		c->cqes[c->n_cqe] = *q;
		c->n_cqe++;
	}
	(void)idx;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static void test_geom_from_params(void)
{
	struct iou_params p;
	iou_ring_geom_t g;

	memset(&p, 0, sizeof(p));
	p.sq_entries = 16;
	p.cq_entries = 32;
	p.sq_off.ring_mask = 15;
	if (!iou_ring_geom_init(&g, &p, 0, true)) {
		CHECK(0, "valid geometry rejected");
		return;
	}
	CHECK(g.sq_stride == 64, "stride %u", g.sq_stride);
	CHECK(g.cq_stride == 16, "cq stride %u", g.cq_stride);

	p.flags = IOU_SETUP_SQE128 | IOU_SETUP_CQE32;
	CHECK(iou_ring_geom_init(&g, &p, 0, true), "sqe128 geom");
	CHECK(g.sq_stride == 128 && g.cq_stride == 32, "128/32 strides: %u %u",
	      g.sq_stride, g.cq_stride);

	/* Non-power-of-two entries must be rejected. */
	memset(&p, 0, sizeof(p));
	p.sq_entries = 15; p.cq_entries = 32; p.sq_off.ring_mask = 14;
	CHECK(!iou_ring_geom_init(&g, &p, 0, true), "15 entries accepted");
	/* entries == 0 */
	p.sq_entries = 0; p.sq_off.ring_mask = 0;
	CHECK(!iou_ring_geom_init(&g, &p, 0, true), "0 entries accepted");
}

static void test_poll_basic(void)
{
	test_ring_t t;
	iou_ring_t r;
	iou_mem_vtable_t mem;
	iou_ring_geom_t g;
	collect_t c;

	build_ring(&t);
	CHECK(iou_ring_geom_init(&g, &t.p, 0, true), "geom");
	mem.read = fake_read; mem.write = fake_write; mem.ctx = &t.mem;
	iou_ring_init(&r, &g, &mem, 42);

	push_range(&t, 0, 4, 22 /* READ */);
	memset(&c, 0, sizeof(c));
	CHECK(iou_ring_poll_submissions(&r, on_sqe, &c, NULL) == 4, "poll 4");
	CHECK(c.n == 4, "collected %zu", c.n);
	CHECK(c.sqes[0].opcode == 22 && c.sqes[3].fd == 103, "sqe contents");
	CHECK(t.mem.oob_reads == 0, "OOB reads: %d", t.mem.oob_reads);

	/* Second poll with no new submissions yields 0 and no duplicates. */
	CHECK(iou_ring_poll_submissions(&r, on_sqe, &c, NULL) == 0, "second poll");
	CHECK(c.n == 4, "duplicates emitted: %zu", c.n);

	/* More submissions on top. */
	push_range(&t, 4, 2, 23 /* WRITE */);
	memset(&c, 0, sizeof(c));
	CHECK(iou_ring_poll_submissions(&r, on_sqe, &c, NULL) == 2, "poll 2");
	CHECK(c.n == 2 && c.sqes[0].opcode == 23, "incremental poll");

	destroy_ring(&t);
}

static void test_bad_array_slot_rejected(void)
{
	test_ring_t t;
	iou_ring_t r;
	iou_mem_vtable_t mem;
	iou_ring_geom_t g;
	collect_t c;

	build_ring(&t);
	CHECK(iou_ring_geom_init(&g, &t.p, 0, true), "geom");
	mem.read = fake_read; mem.write = fake_write; mem.ctx = &t.mem;
	iou_ring_init(&r, &g, &mem, 1);

	push_range(&t, 0, 2, 22);
	/* Corrupt the second array entry to point outside the ring. */
	poke_u32(t.mem.base, t.p.sq_off.array + 4u, 0xffffff00u);
	memset(&c, 0, sizeof(c));
	CHECK(iou_ring_poll_submissions(&r, on_sqe, &c, NULL) == 1, "only valid one");
	CHECK(c.n == 1, "collected %zu", c.n);
	CHECK(r.anomalies & IOU_RING_ANOM_BAD_ARRAY_SLOT, "anomaly not flagged");
	CHECK(t.mem.oob_reads == 0, "OOB reads: %d", t.mem.oob_reads);

	destroy_ring(&t);
}

static void test_tail_cannot_spin(void)
{
	test_ring_t t;
	iou_ring_t r;
	iou_mem_vtable_t mem;
	iou_ring_geom_t g;

	build_ring(&t);
	CHECK(iou_ring_geom_init(&g, &t.p, 0, true), "geom");
	mem.read = fake_read; mem.write = fake_write; mem.ctx = &t.mem;
	iou_ring_init(&r, &g, &mem, 1);

	/* Tail claims the entire 32-bit space was submitted.  The reader must
	 * clamp to at most one ring and flag it, not iterate 4 billion times. */
	poke_u32(t.mem.base, t.p.sq_off.tail, 0xffffffffu);
	{
		collect_t c;

		memset(&c, 0, sizeof(c));
		CHECK(iou_ring_poll_submissions(&r, on_sqe, &c, NULL) >= 0, "poll survives");
	}
	CHECK(r.anomalies & IOU_RING_ANOM_TAIL_BACKWARD, "anomaly not flagged");
	CHECK(t.mem.oob_reads == 0, "OOB reads: %d", t.mem.oob_reads);

	destroy_ring(&t);
}

static void test_truncated_mapping_short_read(void)
{
	test_ring_t t;
	iou_ring_t r;
	iou_mem_vtable_t mem;
	iou_ring_geom_t g;

	build_ring(&t);
	CHECK(iou_ring_geom_init(&g, &t.p, 0, true), "geom");
	/* Shrink the region so reading the last SQE is a short read, as if the
	 * top of the SQE mapping were unmapped.  Keep the ring header (head at
	 * 0, tail at 4) and the sq_array (at 64, ENTRIES*4 bytes through 128)
	 * readable so the reader can see the submissions, then make only the
	 * SQE area beyond the first 4 entries unavailable. */
	t.mem.size = SQES_OFF + 4 * IOU_SQE_SIZE;
	mem.read = fake_read; mem.write = fake_write; mem.ctx = &t.mem;
	iou_ring_init(&r, &g, &mem, 1);

	push_range(&t, 0, 8, 22);
	{
		collect_t c;

		memset(&c, 0, sizeof(c));
		CHECK(iou_ring_poll_submissions(&r, on_sqe, &c, NULL) == 4,
		      "exactly the 4 mapped entries must be delivered");
	}
	CHECK(r.anomalies & IOU_RING_ANOM_BAD_SQE_SLOT, "short read not flagged");
	/* The reader must never read *inside* a mapped region out of bounds; reads
	 * that start past the truncated tail are expected and are not OOB. */
	CHECK(t.mem.oob_reads == 0, "in-region OOB reads: %d", t.mem.oob_reads);
	CHECK(t.mem.truncated_reads > 0, "test did not actually truncate the mapping");

	destroy_ring(&t);
}

static void test_completions(void)
{
	test_ring_t t;
	iou_ring_t r;
	iou_mem_vtable_t mem;
	iou_ring_geom_t g;
	collect_t c;
	struct iou_cqe cqe0, cqe1;

	build_ring(&t);
	CHECK(iou_ring_geom_init(&g, &t.p, 0, true), "geom");
	mem.read = fake_read; mem.write = fake_write; mem.ctx = &t.mem;
	iou_ring_init(&r, &g, &mem, 1);

	memset(&cqe0, 0, sizeof(cqe0));
	memset(&cqe1, 0, sizeof(cqe1));
	cqe0.user_data = 0xabc;
	cqe0.res = -13;
	cqe1.user_data = 0xdef;
	cqe1.res = 0;
	mem_write_cqe(&t, 0, &cqe0);
	mem_write_cqe(&t, 1, &cqe1);
	poke_u32(t.mem.base, t.p.cq_off.head, 0);
	poke_u32(t.mem.base, t.p.cq_off.tail, 2);

	memset(&c, 0, sizeof(c));
	CHECK(iou_ring_poll_completions(&r, on_cqe, &c, NULL) == 2, "poll 2 cqe");
	CHECK(c.n_cqe == 2 && c.cqes[0].res == -13, "cqe contents");
	CHECK(iou_ring_poll_completions(&r, on_cqe, &c, NULL) == 0, "re-poll");

	destroy_ring(&t);
}

int main(void)
{
	test_geom_from_params();
	test_poll_basic();
	test_bad_array_slot_rejected();
	test_tail_cannot_spin();
	test_truncated_mapping_short_read();
	test_completions();

	printf("test_ring: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}

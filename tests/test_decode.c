/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_decode.c - the reconstruction contract.
 *
 * These tests are the specification of "还原成和普通系统调用一致的事件":
 * every SQE shape a database or an attacker can produce must decode to the
 * semantic actions and path arguments the equivalent syscall would have, and
 * hostile bytes must never read out of bounds.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iou_op.h"
#include "iou_sqe.h"
#include "iou_version.h"

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

/* Build a zeroed SQE with the given fields.  Mirrors how a program writes the
 * ring entry; deliberately uses byte stores so we exercise the packed layout. */
static void sqe_zero(struct iou_sqe *s)
{
	memset(s, 0, sizeof(*s));
}

static void sqe_set(struct iou_sqe *s, uint8_t opcode, uint8_t flags, int32_t fd,
		    uint64_t addr, uint64_t addr2, uint64_t addr3, uint32_t len,
		    uint64_t off)
{
	sqe_zero(s);
	s->opcode = opcode;
	s->flags = flags;
	s->fd = fd;
	s->addr = addr;
	s->addr2 = addr2;
	s->addr3 = addr3;
	s->len = len;
	s->off = off;
}

/* A submitter whose identity we know; in production this comes from the
 * kernel hook's task_struct, capturing pid/creds at submit time. */
static iou_submitter_t submitter(uint32_t pid, uint32_t uid)
{
	iou_submitter_t w;

	memset(&w, 0, sizeof(w));
	w.pid = w.tid = w.tgid = pid;
	w.ppid = 1;
	w.uid = w.euid = w.fsuid = uid;
	w.gid = w.egid = w.fsgid = uid;
	w.ring_id = 0xdeadbeefull;
	w.ring_fd = 7;
	w.ring_flags = 0;
	return w;
}

static bool has_action(const iou_event_t *e, iou_action_t a)
{
	uint8_t i;

	for (i = 0; i < e->n_actions; i++)
		if (e->actions[i] == a)
			return true;
	return false;
}

/* ------------------------------------------------------------------ */

static void test_catalog_covers_kernel(void)
{
	/* The catalog must cover every opcode the newest header defines, or an
	 * attacker on a new kernel gets an unclassified submission. */
	const iou_op_desc_t *d;
	size_t n = iou_op_count();
	size_t i;

	CHECK(n >= 63, "catalog has %zu entries, expected >= 63", n);
	CHECK(iou_op_lookup(0) != NULL, "opcode 0 must exist");
	CHECK(iou_op_lookup(62) != NULL, "opcode 62 (PIPE) must exist");
	CHECK(iou_op_lookup(63) == NULL, "opcode 63 is beyond the catalog");
	CHECK(iou_op_lookup(255) == NULL, "opcode 255 is beyond the catalog");

	for (i = 0; i < n; i++) {
		d = iou_op_at(i);
		CHECK(d != NULL, "iou_op_at(%zu) NULL", i);
		CHECK(d && d->opcode <= 62, "catalog opcode %u out of range", d ? d->opcode : 999u);
		CHECK(d && d->name && d->name[0], "entry %zu has no name", i);
	}
}

static void test_decode_read(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(4242, 1000);
	iou_decode_status_t st;

	sqe_set(&s, 22 /* READ */, 0, 42, 0x1000, 0, 0, 512, 0);
	st = iou_decode_sqe(&s, 64, NULL, &w, &e);
	CHECK(st == IOU_DECODE_OK, "READ decode status %d", st);
	CHECK(e.n_actions == 1, "READ actions %u", e.n_actions);
	CHECK(has_action(&e, IOU_ACT_FILE_READ), "READ must map to file_read");
	CHECK(e.eq_syscall[0] == 0, "READ eq syscall %d", e.eq_syscall[0]);
	CHECK(e.pid == 4242 && e.tgid == 4242, "identity lost: pid=%u tgid=%u", e.pid, e.tgid);
	CHECK(e.euid == 1000, "euid %u", e.euid);
	CHECK(e.ring_id == 0xdeadbeefull, "ring id lost");
	CHECK(e.fd == 42 && e.len == 512 && e.offset == 0, "args fd=%d len=%u off=%llu",
	      e.fd, e.len, (unsigned long long)e.offset);
}

static void test_decode_openat_has_path(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(1, 0);

	/* openat(dirfd=AT_FDCWD, path, flags, mode) via io_uring:
	 * fd=AT_FDCWD, addr=path ptr, open_flags, len=mode */
	sqe_set(&s, 18 /* OPENAT */, 0, -100, 0x7f0000000000ull, 0, 0, 0644, 0);
	s.open_flags = 0x242; /* O_CREAT|O_RDWR-ish */

	if (iou_decode_sqe(&s, 64, NULL, &w, &e) != IOU_DECODE_OK) {
		CHECK(0, "OPENAT should decode");
		return;
	}
	CHECK(has_action(&e, IOU_ACT_FILE_CREATE), "OPENAT -> file_create");
	CHECK(e.path1.present == 1, "OPENAT must carry a path");
	CHECK(e.path1.dfd == -100, "OPENAT dfd %d", e.path1.dfd);
	CHECK(e.path1.user_ptr == 0x7f0000000000ull, "path ptr lost");
}

static void test_decode_rename_two_paths(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(1, 0);

	/* renameat(old_dfd, old, new_dfd, new): fd=old_dfd, addr=old,
	 * addr2=new, len=new_dfd.  NOTE: openat-style `off` and `addr2` share
	 * the same 8 bytes (SQE union), so we must not also write `off` here. */
	sqe_set(&s, 35 /* RENAMEAT */, 0, 3, 0xaaaa, 0, 0, 5, 0);
	s.addr2 = 0xbbbb;
	CHECK(iou_decode_sqe(&s, 64, NULL, &w, &e) == IOU_DECODE_OK, "RENAMEAT decode");
	CHECK(has_action(&e, IOU_ACT_FILE_RENAME), "RENAMEAT -> file_rename");
	CHECK(e.path1.present && e.path1.dfd == 3, "old dfd %d", e.path1.dfd);
	CHECK(e.path2.present && e.path2.dfd == 5, "new dfd %d", e.path2.dfd);
	CHECK(e.path1.user_ptr == 0xaaaa && e.path2.user_ptr == 0xbbbb, "paths swapped");
}

static void test_decode_splice_two_actions(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(1, 0);

	sqe_set(&s, 30 /* SPLICE */, 0, 9, 0, 0, 0, 128, 0);
	s.splice_fd_in = 10;
	CHECK(iou_decode_sqe(&s, 64, NULL, &w, &e) == IOU_DECODE_OK, "SPLICE decode");
	CHECK(e.n_actions == 2, "SPLICE must imply 2 actions, got %u", e.n_actions);
	CHECK(has_action(&e, IOU_ACT_FILE_WRITE) && has_action(&e, IOU_ACT_FILE_READ),
	      "SPLICE must read+write");
}

static void test_decode_fallocate_field_swap(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(1, 0);

	/* fallocate: off=offset, len=mode, addr=length */
	sqe_set(&s, 17 /* FALLOCATE */, 0, 3, 4096 /*len*/, 0, 0, 0x2 /*mode*/,
		1024 /*off*/);
	CHECK(iou_decode_sqe(&s, 64, NULL, &w, &e) == IOU_DECODE_OK, "FALLOCATE decode");
	CHECK(e.len == 4096, "FALLOCATE length must come from addr, got %u", e.len);
	CHECK(e.offset == 1024, "FALLOCATE offset %llu", (unsigned long long)e.offset);
}

static void test_unknown_opcode_fails_closed(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(1, 0);

	sqe_set(&s, 200 /* not in catalog */, 0, 0, 0, 0, 0, 0, 0);
	CHECK(iou_decode_sqe(&s, 64, NULL, &w, &e) == IOU_DECODE_UNKNOWN_OP,
	      "unknown opcode must report UNKNOWN_OP");
	CHECK(e.op_flags & IOU_OPF_UNKNOWN_OPCODE, "unknown opcode flag not set");
	CHECK(e.n_actions == 0, "unknown opcode must yield no actions");

	/* With caps from a 6.16 kernel, opcode 200 is beyond last_op and must
	 * additionally be flagged as a guessed future opcode. */
	{
		iou_caps_t caps;

		iou_caps_init_from_release(&caps, "6.16.0");
		iou_decode_sqe(&s, 64, &caps, &w, &e);
		CHECK(e.op_flags & IOU_OPF_FUTURE_OPCODE,
		      "opcode above last_op must be FUTURE_OPCODE");
	}
}

static void test_version_gating_prevents_false_positives(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(1, 0);
	iou_caps_t caps;

	/* IORING_OP_BIND exists only from 6.11.  On a 6.6 kernel the SQE must
	 * decode as unsupported, never as an executed net_connect. */
	iou_caps_init_from_release(&caps, "6.6.30-generic");
	sqe_set(&s, 56 /* BIND */, 0, 3, 0x1000, 20, 0, 0, 0);
	CHECK(iou_decode_sqe(&s, 64, &caps, &w, &e) == IOU_DECODE_UNSUPPORTED_OP,
	      "BIND on 6.6 must be UNSUPPORTED");
	CHECK(!has_action(&e, IOU_ACT_NET_CONNECT),
	      "BIND on 6.6 must not yield a net action");

	/* Same SQE on 6.16 is a real, supported operation. */
	iou_caps_init_from_release(&caps, "6.16.0-rc1");
	CHECK(iou_decode_sqe(&s, 64, &caps, &w, &e) == IOU_DECODE_OK,
	      "BIND on 6.16 must decode OK");
	CHECK(has_action(&e, IOU_ACT_NET_CONNECT), "BIND on 6.16 -> net_connect");
}

static void test_live_probe_overrides_release(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(1, 0);
	iou_caps_t caps;
	/* A probe buffer: header + entries.  Mark opcode 22 (READ) supported,
	 * 18 (OPENAT) NOT supported, last_op = 22.  This models a stripped-down
	 * downstream kernel. */
	uint8_t probe[16 + 23 * 8];

	memset(probe, 0, sizeof(probe));
	iou_caps_init_from_release(&caps, "6.6.0");
	probe[0] = 22;   /* last_op */
	probe[1] = 23;   /* ops_len */
	/* entry for opcode 22: op byte at +0 (the kernel always sets it to the
	 * index; the decoder rejects a desynchronised array), flags at +2. */
	probe[16 + 22 * 8 + 0] = 22;
	probe[16 + 22 * 8 + 2] = 1;  /* IO_URING_OP_SUPPORTED */
	iou_caps_apply_probe(&caps, probe, sizeof(probe));
	CHECK(caps.probed, "caps not marked probed");
	CHECK(iou_caps_supports(&caps, 22), "probe says READ supported");
	CHECK(!iou_caps_supports(&caps, 18), "probe says OPENAT unsupported");

	sqe_set(&s, 22, 0, 3, 0, 0, 0, 0, 0);
	CHECK(iou_decode_sqe(&s, 64, &caps, &w, &e) == IOU_DECODE_OK,
	      "probed-supported op must decode");
	sqe_set(&s, 18, 0, -100, 0x1000, 0, 0, 0, 0);
	CHECK(iou_decode_sqe(&s, 64, &caps, &w, &e) == IOU_DECODE_UNSUPPORTED_OP,
	      "probed-unsupported op must be gated even though the release says yes");
}

static void test_bad_flags_and_alignment(void)
{
	struct iou_sqe s;
	iou_event_t e;
	uint8_t buf[IOU_SQE_SIZE + 8];
	uint8_t *misaligned = buf + 1;

	/* Bit 7 of flags is invalid; kernel would -EINVAL.  We report it. */
	sqe_set(&s, 22, 0x80, 3, 0, 0, 0, 0, 0);
	CHECK(iou_decode_sqe(&s, 64, NULL, NULL, &e) == IOU_DECODE_MALFORMED_SQE,
	      "bad flags must be MALFORMED");
	CHECK(e.op_flags & IOU_OPF_BAD_FLAGS, "bad flags flag not set");

	/* Decoding from an odd address must produce identical results (memcpy
	 * reads, not aligned loads). */
	memset(buf, 0, sizeof(buf));
	memcpy(misaligned, &s, IOU_SQE_SIZE);
	CHECK(iou_decode_sqe((const struct iou_sqe *)misaligned, 64, NULL, NULL, &e)
	      == IOU_DECODE_MALFORMED_SQE, "misaligned decode must work");

	sqe_set(&s, 22, 0, 8, 0, 0, 0, 64, 0);
	memcpy(misaligned, &s, IOU_SQE_SIZE);
	{
		iou_event_t a, b;
		CHECK(iou_decode_sqe(&s, 64, NULL, NULL, &a) == IOU_DECODE_OK, "aligned");
		CHECK(iou_decode_sqe((const struct iou_sqe *)misaligned, 64, NULL, NULL, &b)
		      == IOU_DECODE_OK, "misaligned");
		CHECK(a.opcode == b.opcode && a.fd == b.fd && a.len == b.len,
		      "misaligned read disagreed with aligned read");
	}
}

static void test_bad_stride_rejected(void)
{
	struct iou_sqe s;
	iou_event_t e;

	sqe_set(&s, 22, 0, 3, 0, 0, 0, 0, 0);
	CHECK(iou_decode_sqe(&s, 48, NULL, NULL, &e) == IOU_DECODE_MALFORMED_SQE,
	      "stride 48 must be rejected");
	CHECK(iou_decode_sqe(&s, 128, NULL, NULL, &e) == IOU_DECODE_OK,
	      "stride 128 must be accepted");
	CHECK(e.op_flags & IOU_OPF_CMD_PASSTHROUGH, "SQE128 must be flagged");
}

static void test_union_off_addr2_not_confused(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(1, 0);

	/* A READ has an offset at bytes 8..15 and no addr2; an OPENAT2 has an
	 * addr2 (the open_how pointer) at the same bytes and no offset.  The
	 * decoder must never report both from the same 8 bytes. */
	sqe_set(&s, 22 /* READ */, 0, 3, 0, 0, 0, 64, 4096 /* off */);
	if (iou_decode_sqe(&s, 64, NULL, &w, &e) == IOU_DECODE_OK) {
		CHECK(e.offset == 4096, "READ offset %llu", (unsigned long long)e.offset);
		CHECK(e.addr2 == 0, "READ must not fabricate an addr2 (%llu)",
		      (unsigned long long)e.addr2);
	}
	sqe_set(&s, 28 /* OPENAT2 */, 0, -100, 0x1000, 0, 0, 24, 0);
	s.addr2 = 0x2000; /* open_how pointer lives at bytes 8..15 */
	if (iou_decode_sqe(&s, 64, NULL, &w, &e) == IOU_DECODE_OK) {
		CHECK(e.addr2 == 0x2000, "OPENAT2 addr2 %llu",
		      (unsigned long long)e.addr2);
		CHECK(e.offset == 0, "OPENAT2 must not fabricate an offset (%llu)",
		      (unsigned long long)e.offset);
	}
}

static void test_completion_attribution(void)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w = submitter(999, 555);

	sqe_set(&s, 22, 0, 3, 0, 0, 0, 0, 0);
	iou_decode_sqe(&s, 64, NULL, &w, &e);
	CHECK(iou_event_complete(&e, -13 /* EACCES */, 12345) == true,
	      "first completion must attach");
	CHECK(e.completed && e.result == -13 && e.result_errno == 13,
	      "completion result wrong: %lld errno %u", (long long)e.result, e.result_errno);
	CHECK(e.pid == 999, "submitter attribution must survive completion");
	/* A second CQE for the same non-multishot request is a duplicate. */
	CHECK(iou_event_complete(&e, 0, 99999) == false, "duplicate completion accepted");
}

int main(void)
{
	test_catalog_covers_kernel();
	test_decode_read();
	test_decode_openat_has_path();
	test_decode_rename_two_paths();
	test_decode_splice_two_actions();
	test_decode_fallocate_field_swap();
	test_unknown_opcode_fails_closed();
	test_version_gating_prevents_false_positives();
	test_live_probe_overrides_release();
	test_bad_flags_and_alignment();
	test_bad_stride_rejected();
	test_union_off_addr2_not_confused();
	test_completion_attribution();

	printf("test_decode: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}

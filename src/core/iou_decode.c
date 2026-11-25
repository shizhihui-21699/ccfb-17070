/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_decode.c - turn one raw SQE into a syscall-equivalent iou_event_t.
 *
 * This file is the "还原" (reconstruction) step: it is the single place where
 * opcode-specific argument layout knowledge lives, so that the rest of the
 * component (rules engine, audit emitter, keeper) never has to know which
 * field of the SQE meant what.
 *
 * HARDENING NOTES
 * ---------------
 * The SQE is attacker-controlled bytes.  We therefore:
 *   - read every field through memcpy into a local, so a misaligned or
 *     partially-written SQE cannot produce a torn read that disagrees with
 *     the kernel's READ_ONCE() of the same field;
 *   - never dereference sqe->addr / addr2 / addr3 (those are userspace
 *     pointers).  They are copied into the event as raw numbers for the
 *     audit trail, and any actual path resolution happens later, in the
 *     submitter's context, by the component that has safe access to user
 *     memory.  A pointer that is obviously not canonical is still recorded
 *     (it may itself be the signal), but never followed here.
 */
#include <string.h>

#include "iou_op.h"

/* ------------------------------------------------------------------ */
/* Field reads                                                         */
/* ------------------------------------------------------------------ */

/*
 * On x86_64 the SQE is 8-byte aligned in the ring, but on other arches and
 * with a hostile producer it need not be.  Read each scalar with memcpy; all
 * loads stay in-bounds because the union members are within the 64-byte
 * struct we were handed (stride checked by the caller via sizeof).
 */
#define RD8(dst, p, off)  memcpy(&(dst), (const uint8_t *)(p) + (off), sizeof(dst))

static inline int32_t rd_i32(const struct iou_sqe *s, size_t off)
{
	int32_t v;
	RD8(v, s, off);
	return v;
}

static inline uint32_t rd_u32(const struct iou_sqe *s, size_t off)
{
	uint32_t v;
	RD8(v, s, off);
	return v;
}

static inline uint64_t rd_u64(const struct iou_sqe *s, size_t off)
{
	uint64_t v;
	RD8(v, s, off);
	return v;
}

static inline uint16_t rd_u16(const struct iou_sqe *s, size_t off)
{
	uint16_t v;
	RD8(v, s, off);
	return v;
}

/* Offsets within the packed layout (see iou_sqe.h). */
#define SQE_OPCODE      0u
#define SQE_FLAGS       1u
#define SQE_IOPRIO      2u
#define SQE_FD          4u
#define SQE_OFF         8u
#define SQE_ADDR2       8u
#define SQE_CMD_OP     12u
#define SQE_ADDR       16u
#define SQE_LEVEL      20u
#define SQE_OPTNAME    20u
#define SQE_LEN        24u
#define SQE_FLAGS2     28u
#define SQE_USER_DATA  32u
#define SQE_BUF_INDEX  40u
#define SQE_PERSONALITY 42u
#define SQE_FILE_INDEX 44u
#define SQE_ADDR_LEN   44u
#define SQE_SPLICE_FD_IN 44u
#define SQE_ADDR3      48u

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static uint32_t errno_from_res(int64_t res)
{
	/* kernel CQE res is -(errno) for failures; errno values are < 4096 */
	if (res < 0 && res >= -4095)
		return (uint32_t)(-res);
	return 0;
}

static void set_path(iou_path_arg_t *p, int present, int32_t dfd, uint64_t ptr)
{
	p->present = present ? 1u : 0u;
	p->is_relative = (present && dfd != -1) ? 1u : 0u;
	p->dfd = present ? dfd : -1;
	p->user_ptr = ptr;
}

/*
 * Fill the path slots for opcodes that take filesystem paths, using the
 * exact dfd/path argument mapping in the kernel prep functions.  This is the
 * bridge that lets a rules engine keying on "read of /etc/shadow" work when
 * the read is spelled openat+read instead: the openat carries the path.
 */
static void fill_paths(const iou_op_desc_t *d, const struct iou_sqe *s,
		       iou_event_t *ev, int32_t fd, uint64_t addr,
		       uint64_t addr2, uint64_t addr3, uint32_t len)
{
	(void)len;
	(void)s;

	if (d->uses_path1) {
		/* Default: addr is the primary path, fd is its dfd. */
		uint64_t path = addr;
		int32_t dfd = fd;

		switch (d->opcode) {
		case 38 /* SYMLINKAT */:
			/* fd = new_dfd, addr = target, addr2 = newpath */
			path = addr2;
			dfd = fd;
			break;
		case 42 /* SETXATTR */:
		case 44 /* GETXATTR */:
			path = addr3;
			dfd = -1; /* AT_FDCWD: these take a plain path */
			break;
		default:
			break;
		}
		set_path(&ev->path1, 1, dfd, path);
	}

	if (d->uses_path2) {
		/* Second path is always addr2 except linkat/renameat, where it is
		 * newpath and len carries the destination dfd. */
		uint32_t new_dfd = len;
		uint64_t path2 = addr2;

		switch (d->opcode) {
		case 35 /* RENAMEAT */:
		case 39 /* LINKAT */:
			set_path(&ev->path2, 1, (int32_t)new_dfd, path2);
			break;
		case 38 /* SYMLINKAT */:
			set_path(&ev->path2, 1, fd, addr2);
			break;
		default:
			set_path(&ev->path2, 1, -1, path2);
			break;
		}
	}
}

/* ------------------------------------------------------------------ */
/* Decode                                                              */
/* ------------------------------------------------------------------ */

iou_decode_status_t iou_decode_sqe(const struct iou_sqe *sqe, uint32_t stride,
				   const iou_caps_t *caps,
				   const iou_submitter_t *who,
				   iou_event_t *out)
{
	const iou_op_desc_t *d;
	uint8_t opcode, flags;
	uint32_t len, f2;
	uint64_t addr, addr2, addr3;
	int32_t fd;
	uint16_t personality;
	int i;

	if (out == NULL)
		return IOU_DECODE_MALFORMED_SQE;
	memset(out, 0, sizeof(*out));

	if (sqe == NULL || (stride != IOU_SQE_SIZE && stride != IOU_SQE128_SIZE))
		return IOU_DECODE_MALFORMED_SQE;

	opcode = ((const uint8_t *)sqe)[SQE_OPCODE];
	flags  = ((const uint8_t *)sqe)[SQE_FLAGS];

	fd        = rd_i32(sqe, SQE_FD);
	addr      = rd_u64(sqe, SQE_ADDR);
	addr2     = rd_u64(sqe, SQE_ADDR2);
	addr3     = rd_u64(sqe, SQE_ADDR3);
	len       = rd_u32(sqe, SQE_LEN);
	f2        = rd_u32(sqe, SQE_FLAGS2);
	personality = rd_u16(sqe, SQE_PERSONALITY);

	/* ---- identity ---- */
	if (who != NULL) {
		out->pid  = who->pid;
		out->tid  = who->tid;
		out->tgid = who->tgid;
		out->ppid = who->ppid;
		out->uid  = who->uid;
		out->gid  = who->gid;
		out->euid = who->euid;
		out->egid = who->egid;
		out->fsuid = who->fsuid;
		out->fsgid = who->fsgid;
		out->personality = who->personality ? who->personality : personality;
		out->cgroup_id = who->cgroup_id;
		out->ring_id = who->ring_id;
		out->ring_fd = who->ring_fd;
		out->ring_flags = who->ring_flags;
	} else {
		out->personality = personality;
	}

	/* ---- ring-relative oddities ---- */
	out->opcode = opcode;
	out->sqe_flags = flags;
	out->fd = fd;
	out->len = len;
	out->addr = addr;
	out->addr2 = addr2;
	out->addr3 = addr3;
	out->user_data = rd_u64(sqe, SQE_USER_DATA);

	/* Bytes 8..15 of an SQE are a union: "off" for some opcodes, "addr2" for
	 * others.  A decoder that fills both always reports one of them wrongly,
	 * which an audit consumer cannot detect.  Fill exactly the one this
	 * opcode means and leave the other zero.  (An opcode that uses neither
	 * gets both zero.) */
	{
		const iou_op_desc_t *pd = iou_op_lookup(opcode);

		if (pd != NULL && pd->uses_addr2) {
			out->addr2 = addr2;
			out->offset = 0;
		} else if (pd != NULL && pd->uses_off) {
			out->offset = rd_u64(sqe, SQE_OFF);
			out->addr2 = 0;
		} else {
			out->offset = 0;
			out->addr2 = 0;
		}
	}

	if (flags & IOU_SQE_FIXED_FILE)
		out->op_flags |= IOU_OPF_FIXED_FILE;
	if (flags & IOU_SQE_ASYNC)
		out->op_flags |= IOU_OPF_FORCED_ASYNC;
	if (personality != 0)
		out->op_flags |= IOU_OPF_CREDS_OVERRIDE;
	if (stride == IOU_SQE128_SIZE)
		out->op_flags |= IOU_OPF_CMD_PASSTHROUGH; /* only meaningful for *_128 */

	/*
	 * Bits the kernel will reject with -EINVAL.  We do not fail the whole
	 * event on them: an SQE with garbage flags is an attempt worth logging,
	 * and the kernel will never execute it anyway.  Mark it so the rules
	 * engine can treat it as hostile rather than benign.
	 */
	if (flags & ~IOU_SQE_FLAGS_VALID_MASK) {
		out->op_flags |= IOU_OPF_BAD_FLAGS;
		return IOU_DECODE_MALFORMED_SQE;
	}

	/* ---- catalog lookup, with kernel-awareness ---- */
	d = iou_op_lookup(opcode);
	if (d == NULL) {
		out->op_flags |= IOU_OPF_UNKNOWN_OPCODE;
		out->op_introduced_in = 0;
		if (caps != NULL && !iou_caps_is_known_number(caps, opcode))
			out->op_flags |= IOU_OPF_FUTURE_OPCODE;
		return IOU_DECODE_UNKNOWN_OP;
	}

	out->op_introduced_in = d->introduced_in;

	if (caps != NULL && !iou_caps_supports(caps, opcode)) {
		/* Valid opcode number in our catalog, but this kernel cannot run
		 * it.  Not an execution attempt; do not let it fire policy. */
		out->op_flags |= IOU_OPF_NOT_IN_KERNEL;
		return IOU_DECODE_UNSUPPORTED_OP;
	}

	out->primary_op_is_known = 1;
	out->n_actions = d->n_actions;
	for (i = 0; i < d->n_actions && i < IOU_MAX_EVENT_ACTIONS; i++) {
		out->actions[i] = d->actions[i];
		out->eq_syscall[i] = d->eq_syscall[i];
	}
	if (d->always_async)
		out->op_flags |= IOU_OPF_FORCED_ASYNC;
	if (d->is_multishot)
		out->op_flags |= IOU_OPF_MULTISHOT;
	if (opcode == 46 /* URING_CMD */)
		out->op_flags |= IOU_OPF_CMD_PASSTHROUGH;

	fill_paths(d, sqe, out, fd, addr, addr2, addr3, len);

	/* ---- opcode-specific field re-interpretation ---- */
	/*
	 * Most of the field mapping is captured by fill_paths().  A few opcodes
	 * overload sqe fields in ways the generic view would misreport; record
	 * the corrected values so the audit output matches what the kernel
	 * actually did.
	 */
	switch (opcode) {
	case 17: /* FALLOCATE: len is mode, addr is length */
		out->len = (uint32_t)addr;
		out->addr = 0;
		break;
	case 45: /* SOCKET: fd is domain, off is type, len is protocol */
		out->fd = -1;
		out->offset = 0;
		break;
	case 55: /* FTRUNCATE: addr is the new length */
		out->len = (uint32_t)addr;
		out->addr = 0;
		break;
	case 50: /* WAITID: fd is idtype, addr is id, addr2 is infop, len options */
		out->fd = -1;
		break;
	case 30: /* SPLICE: splice_fd_in (offset 44) is the input fd */
		out->fd = fd;
		break;
	case 33: /* TEE: same input-fd-overload as splice */
		break;
	case 42: /* SETXATTR: len is value size; addr is name */
	case 44: /* GETXATTR */
		/* leave len as the value size, addr as xattr name */
		break;
	case 41: /* FSETXATTR */
	case 43: /* FGETXATTR */
		break;
	default:
		break;
	}

	(void)f2; /* reserved for future per-op flag fields */

	return IOU_DECODE_OK;
}

bool iou_event_complete(iou_event_t *ev, int32_t cqe_res, uint64_t ts_ns)
{
	if (ev == NULL)
		return false;
	if (ev->completed)
		return false;
	ev->result = cqe_res;
	ev->result_errno = (uint8_t)errno_from_res(cqe_res);
	ev->completed = 1;
	ev->complete_ts_ns = ts_ns;
	return true;
}

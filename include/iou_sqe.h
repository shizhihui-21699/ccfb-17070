/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_sqe.h - byte-exact, dependency-free mirror of the io_uring userspace
 * ABI (include/uapi/linux/io_uring.h).
 *
 * WHY THIS EXISTS
 * ---------------
 * The audit component must decode submission-queue entries (SQEs) that were
 * written by an attacker-controlled process.  Two rules follow from that:
 *
 *   1. We never include <linux/io_uring.h>.  On a hardened host the header
 *      may be absent (no kernel-devel package), and on a distro kernel it may
 *      be older than the running kernel -- io_uring's UAPI grows every
 *      release.  A missing opcode must never cause us to under-report.
 *      Everything we need is transcribed here and pinned with static asserts
 *      against the sizes/offsets the kernel itself uses.
 *
 *   2. The struct is `packed`.  Attackers get to place arbitrary bytes in the
 *      ring; we must interpret them exactly as the kernel does on every
 *      architecture, not as this compiler happens to lay out a bitfield.
 *
 * The ABI has been stable since Linux 5.1 (the SQE is 64 bytes; SQE128 rings
 * add a second 64-byte half used only by cmd passthrough).  That stability is
 * what makes a single portable decoder viable across 5.1 .. current.
 */
#ifndef IOU_SQE_H
#define IOU_SQE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IOU_SQE_SIZE          64u
#define IOU_SQE128_SIZE      128u
#define IOU_CQE_SIZE          16u
#define IOU_CQE32_SIZE        32u

/* Maximum entries the kernel will ever hand out for one ring (IORING_MAX_ENTRIES) */
#define IOU_MAX_ENTRIES   32768u
#define IOU_MAX_CQ_ENTRIES (2u * IOU_MAX_ENTRIES)

/* ------------------------------------------------------------------ */
/* SQE                                                                 */
/* ------------------------------------------------------------------ */

struct iou_sqe {
	uint8_t  opcode;
	uint8_t  flags;
	uint16_t ioprio;
	int32_t  fd;

	union {
		uint64_t off;
		uint64_t addr2;
		struct {
			uint32_t cmd_op;
			uint32_t pad1;
		};
	};

	union {
		uint64_t addr;
		uint64_t splice_off_in;
		struct {
			uint32_t level;
			uint32_t optname;
		};
	};

	uint32_t len;

	union {
		uint32_t rw_flags;
		uint32_t fsync_flags;
		uint32_t poll32_events;
		uint32_t sync_range_flags;
		uint32_t msg_flags;
		uint32_t timeout_flags;
		uint32_t accept_flags;
		uint32_t cancel_flags;
		uint32_t open_flags;
		uint32_t statx_flags;
		uint32_t fadvise_advice;
		uint32_t splice_flags;
		uint32_t rename_flags;
		uint32_t unlink_flags;
		uint32_t hardlink_flags;
		uint32_t xattr_flags;
		uint32_t msg_ring_flags;
		uint32_t uring_cmd_flags;
		uint32_t waitid_flags;
		uint32_t futex_flags;
		uint32_t install_fd_flags;
		uint32_t nop_flags;
		uint32_t pipe_flags;
		uint32_t mode;           /* fallocate / mkdirat overloading */
		uint32_t flags2;         /* neutral name for the decoder */
	};

	uint64_t user_data;

	uint16_t buf_index;      /* or buf_group */
	uint16_t personality;

	union {
		int32_t  splice_fd_in;
		uint32_t file_index;
		uint32_t zcrx_ifq_idx;
		uint32_t optlen;
		struct {
			uint16_t addr_len;
			uint16_t pad3;
		};
		struct {
			uint8_t  write_stream;
			uint8_t  pad4[3];
		};
	};

	union {
		struct {
			uint64_t addr3;
			uint64_t pad2;
		};
		uint64_t optval;
	};
} __attribute__((packed));

/* SQE128: the kernel reads opcode/flags/etc from the first 64 bytes only for
 * standard opcodes; the second half is command payload for *_128 opcodes. */
struct iou_sqe128 {
	struct iou_sqe sqe;
	uint8_t ext[64];
} __attribute__((packed));

/* ------------------------------------------------------------------ */
/* CQE                                                                 */
/* ------------------------------------------------------------------ */

struct iou_cqe {
	uint64_t user_data;
	int32_t  res;
	uint32_t flags;
} __attribute__((packed));

struct iou_cqe32 {
	struct iou_cqe cqe;
	uint64_t big0;
	uint64_t big1;
} __attribute__((packed));

/* ------------------------------------------------------------------ */
/* Ring geometry / params                                              */
/* ------------------------------------------------------------------ */

struct iou_sqring_offsets {
	uint32_t head;
	uint32_t tail;
	uint32_t ring_mask;
	uint32_t ring_entries;
	uint32_t flags;
	uint32_t dropped;
	uint32_t array;
	uint32_t resv1;
	uint64_t user_addr;
} __attribute__((packed));

struct iou_cqring_offsets {
	uint32_t head;
	uint32_t tail;
	uint32_t ring_mask;
	uint32_t ring_entries;
	uint32_t overflow;
	uint32_t cqes;
	uint32_t flags;
	uint32_t resv1;
	uint64_t user_addr;
} __attribute__((packed));

struct iou_params {
	uint32_t sq_entries;
	uint32_t cq_entries;
	uint32_t flags;
	uint32_t sq_thread_cpu;
	uint32_t sq_thread_idle;
	uint32_t features;
	uint32_t wq_fd;
	uint32_t resv[3];
	struct iou_sqring_offsets sq_off;
	struct iou_cqring_offsets cq_off;
} __attribute__((packed));

struct iou_probe_op {
	uint8_t  op;
	uint8_t  resv;
	uint16_t flags;
	uint32_t resv2;
} __attribute__((packed));

/* Header of struct io_uring_probe: last_op, ops_len, 2 bytes resv, 3x u32 resv2.
 * ops[] (struct io_uring_probe_op) follows immediately at offset 16.  Declared
 * as an offset/size pair rather than a flexible array so the layout is
 * explicit and portable. */
#define IOU_PROBE_HDR_SIZE 16u
#define IOU_PROBE_OP_SIZE   8u

/* ------------------------------------------------------------------ */
/* Flags                                                               */
/* ------------------------------------------------------------------ */

/* io_uring_setup() flags */
#define IOU_SETUP_IOPOLL          (1u << 0)
#define IOU_SETUP_SQPOLL          (1u << 1)
#define IOU_SETUP_SQ_AFF          (1u << 2)
#define IOU_SETUP_CQSIZE          (1u << 3)
#define IOU_SETUP_CLAMP           (1u << 4)
#define IOU_SETUP_ATTACH_WQ       (1u << 5)
#define IOU_SETUP_R_DISABLED      (1u << 6)
#define IOU_SETUP_SUBMIT_ALL      (1u << 7)
#define IOU_SETUP_COOP_TASKRUN    (1u << 8)
#define IOU_SETUP_TASKRUN_FLAG    (1u << 9)
#define IOU_SETUP_SQE128          (1u << 10)
#define IOU_SETUP_CQE32           (1u << 11)
#define IOU_SETUP_SINGLE_ISSUER   (1u << 12)
#define IOU_SETUP_DEFER_TASKRUN   (1u << 13)
#define IOU_SETUP_NO_MMAP         (1u << 14)
#define IOU_SETUP_REGISTERED_FD_ONLY (1u << 15)
#define IOU_SETUP_NO_SQARRAY      (1u << 16)

/* SQ ring flags */
#define IOU_SRING_NEED_WAKEUP     (1u << 0)
#define IOU_SRING_CQ_OVERFLOW     (1u << 1)
#define IOU_SRING_SQ_DRAINING     (1u << 2)
#define IOU_SRING_SQ_READY        (1u << 3)

/* SQE flags (IOSQE_*) */
#define IOU_SQE_FIXED_FILE        (1u << 0)
#define IOU_SQE_IO_DRAIN          (1u << 1)
#define IOU_SQE_IO_LINK           (1u << 2)
#define IOU_SQE_IO_HARDLINK       (1u << 3)
#define IOU_SQE_ASYNC             (1u << 4)
#define IOU_SQE_BUFFER_SELECT     (1u << 5)
#define IOU_SQE_CQE_SKIP_SUCCESS  (1u << 6)

/* CQE flags */
#define IOU_CQE_F_MORE            (1u << 1)
#define IOU_CQE_F_SOCK_NONEMPTY   (1u << 2)
#define IOU_CQE_F_NOTIF           (1u << 3)

/* io_uring_register() opcodes we care about */
#define IOU_REGISTER_BUFFERS            0
#define IOU_REGISTER_FILES              2
#define IOU_REGISTER_EVENTFD            4
#define IOU_REGISTER_FILES_UPDATE       6
#define IOU_REGISTER_PROBE              8
#define IOU_REGISTER_PERSONALITY        9
#define IOU_REGISTER_RESTRICTIONS      11
#define IOU_REGISTER_ENABLE_RINGS      12
#define IOU_REGISTER_FILES2            13
#define IOU_REGISTER_FILES_UPDATE2     14
#define IOU_REGISTER_RING_FDS          20
#define IOU_REGISTER_SYNC_CANCEL       24
#define IOU_REGISTER_FILE_ALLOC_RANGE  25

/* probe op flags */
#define IOU_PROBE_OP_SUPPORTED        (1u << 0)

/* IORING_REGISTER_RESTRICTIONS: an empty opcode allow-list kills a ring, and
 * the kernel refuses to widen a set once installed.  We use this as one of the
 * mechanisms for "disable the interface for this process". */
#define IOU_RESTRICTION_REGISTER_OP   0
#define IOU_RESTRICTION_SQE_OP        1
#define IOU_RESTRICTION_SQE_FLAGS_ALLOWED 2

/* ------------------------------------------------------------------ */
/* Compile-time guarantees                                             */
/* ------------------------------------------------------------------ */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct iou_sqe)  == IOU_SQE_SIZE,  "io_uring SQE must be 64 bytes");
_Static_assert(sizeof(struct iou_sqe128) == IOU_SQE128_SIZE, "SQE128 must be 128 bytes");
_Static_assert(sizeof(struct iou_cqe)  == IOU_CQE_SIZE,  "io_uring CQE must be 16 bytes");
_Static_assert(sizeof(struct iou_cqe32) == IOU_CQE32_SIZE, "CQE32 must be 32 bytes");
_Static_assert(sizeof(struct iou_params) == 120u, "io_uring_params must be 120 bytes");
_Static_assert(offsetof(struct iou_sqe, user_data)  == 32u, "sqe->user_data offset");
_Static_assert(offsetof(struct iou_sqe, len)        == 24u, "sqe->len offset");
_Static_assert(offsetof(struct iou_sqe, personality) == 42u, "sqe->personality offset");
_Static_assert(offsetof(struct iou_sqe, addr3)      == 48u, "sqe->addr3 offset");
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static inline uint32_t iou_sqe_stride(uint32_t setup_flags)
{
	return (setup_flags & IOU_SETUP_SQE128) ? IOU_SQE128_SIZE : IOU_SQE_SIZE;
}

static inline uint32_t iou_cqe_stride(uint32_t setup_flags)
{
	return (setup_flags & IOU_SETUP_CQE32) ? IOU_CQE32_SIZE : IOU_CQE_SIZE;
}

/* Mask that the kernel accepts in sqe->flags.  A set bit outside this mask
 * makes io_init_req() reject the request with -EINVAL; we therefore treat an
 * out-of-mask bit as an attempt to smuggle semantics past us. */
#define IOU_SQE_FLAGS_VALID_MASK \
	(IOU_SQE_FIXED_FILE | IOU_SQE_IO_DRAIN | IOU_SQE_IO_LINK | \
	 IOU_SQE_IO_HARDLINK | IOU_SQE_ASYNC | IOU_SQE_BUFFER_SELECT | \
	 IOU_SQE_CQE_SKIP_SUCCESS)

#ifdef __cplusplus
}
#endif

#endif /* IOU_SQE_H */

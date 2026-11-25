/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_op.h - opcode catalog and SQE -> "syscall-equivalent event" decoder.
 *
 * THE DESIGN DECISION
 * -------------------
 * "Different kernel versions support wildly different operation types" is not
 * solved by a bigger table.  It is solved by never keying policy on the
 * opcode number at all.
 *
 * Every SQE is decomposed into up to three *semantic* actions:
 *
 *     FILE_READ  FILE_WRITE  FILE_CREATE  FILE_DELETE  FILE_RENAME
 *     FILE_META  FILE_XATTR   NET_CONNECT  NET_LISTEN   NET_ACCEPT
 *     NET_SEND   NET_RECV     PROC_CREATE  PROC_WAIT    FS_CONTROL
 *
 * and every semantic action carries the syscall family it is equivalent to
 * (openat, unlinkat, connect, execve-ish, ...).  The existing syscall-hook
 * rules are written against those semantic actions, so they match identically
 * whether the attacker used openat(2), or IORING_OP_OPENAT on 5.19+, or
 * IORING_OP_OPENAT2 on 5.11+ -- and they match even on a kernel where one of
 * those opcodes does not exist, because the catalog entry for an opcode this
 * kernel lacks is simply never produced.
 *
 * `introduced_in` (the release that upstream added the opcode, verified
 * against the uapi headers of 29 kernel tags) is metadata for alerting and for
 * the user-facing docs.  It is NEVER used to decide enforcement: the live
 * IORING_REGISTER_PROBE answer in iou_caps_t is authoritative, so a kernel
 * that lacked an opcode entirely can never fire a false rule.
 *
 * FAILING CLOSED
 * --------------
 * An opcode that is *not* in this catalog (a future kernel added it) decodes
 * to IOU_ACT_UNKNOWN with zero semantic actions.  IOU_ACT_UNKNOWN is, by
 * policy default, treated as a full security event and matched against
 * catch-all rules.  This is deliberate: the alternative -- ignoring unknown
 * opcodes -- is exactly the blind spot an attacker would exploit.
 */
#ifndef IOU_OP_H
#define IOU_OP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "iou_sqe.h"
#include "iou_version.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Semantic action classes                                             */
/* ------------------------------------------------------------------ */

typedef enum {
	IOU_ACT_NONE = 0,
	IOU_ACT_FILE_READ,      /* read bytes out of a file/device         */
	IOU_ACT_FILE_WRITE,     /* write bytes into a file/device          */
	IOU_ACT_FILE_CREATE,    /* open(O_CREAT|O_TMPFILE) / mkdir / symlink / pipe */
	IOU_ACT_FILE_DELETE,    /* unlink / rmdir                          */
	IOU_ACT_FILE_RENAME,    /* rename / link                           */
	IOU_ACT_FILE_META,      /* statx / fallocate / ftruncate / sync / close */
	IOU_ACT_FILE_XATTR,     /* get/setxattr                            */
	IOU_ACT_NET_CONNECT,    /* connect / bind / udp send to addr       */
	IOU_ACT_NET_LISTEN,     /* listen                                  */
	IOU_ACT_NET_ACCEPT,     /* accept / accept4                        */
	IOU_ACT_NET_SEND,       /* send / sendmsg / send_zc                 */
	IOU_ACT_NET_RECV,       /* recv / recvmsg / recv_zc                 */
	IOU_ACT_PROC_CREATE,    /* clone/fork/vfork-class                  */
	IOU_ACT_PROC_WAIT,      /* waitid                                  */
	IOU_ACT_FS_CONTROL,     /* mount, umount, pivot_root, chmod, ... (not yet expressible) */
	IOU_ACT_IPC,            /* msg_ring, eventfd, futex -- ring-internal signalling */
	IOU_ACT_WAIT,           /* poll/epoll readiness notification on an fd      */
	IOU_ACT_MAX
} iou_action_t;

const char *iou_action_name(iou_action_t act);

/* ------------------------------------------------------------------ */
/* The "restored" event                                                */
/* ------------------------------------------------------------------ */

/* An SQE can imply more than one semantic action (e.g. IORING_OP_SPLICE
 * reads one file and writes another).  The decoder emits each into the event
 * so every action can be matched independently. */
#define IOU_MAX_EVENT_ACTIONS 4

typedef struct iou_path_arg {
	uint32_t present;        /* 1 if the SQE carried this path         */
	uint32_t is_relative;    /* 1 -> kernel would resolve against dfd  */
	int32_t  dfd;            /* dirfd used for resolution (-1 = AT_FDCWD) */
	uint64_t user_ptr;       /* raw userspace pointer, for logging only */
} iou_path_arg_t;

typedef struct iou_event {
	/* ---- identity of the submitter, captured AT SUBMIT TIME ---- */
	uint32_t pid;
	uint32_t tid;
	uint32_t tgid;
	uint32_t ppid;
	uint32_t uid, gid, euid, egid, fsuid, fsgid;
	uint32_t personality;    /* registered personality id, 0 = current creds */
	uint64_t cgroup_id;      /* kfunc-time cgroup, 0 = unavailable          */

	/* ---- ring identity ---- */
	uint64_t ring_id;        /* opaque id derived from struct io_ring_ctx   */
	uint32_t ring_fd;        /* fd of the ring in the submitter             */
	int32_t  ring_flags;     /* io_uring_setup() flags                      */

	/* ---- the operation ---- */
	uint8_t  opcode;
	uint8_t  sqe_flags;
	uint64_t user_data;
	int32_t  fd;             /* sqe->fd, -1 if unused                       */
	uint32_t len;
	uint64_t offset;
	uint64_t addr;
	uint64_t addr2;
	uint64_t addr3;

	/* ---- the syscall-equivalent reconstruction ---- */
	uint8_t  n_actions;
	uint8_t  primary_op_is_known;
	uint8_t  reserved_[2];
	iou_action_t actions[IOU_MAX_EVENT_ACTIONS];
	int32_t  eq_syscall[IOU_MAX_EVENT_ACTIONS]; /* __NR_* on x86_64, -1 unknown */

	/* ---- path arguments for the actions that take paths ---- */
	iou_path_arg_t path1;
	iou_path_arg_t path2;

	/* ---- outcome (filled from the CQE) ---- */
	int64_t  result;
	uint8_t  completed;
	uint8_t  result_errno;   /* -res if res<0, else 0                       */
	uint8_t  is_async;       /* executed on a kernel worker thread          */
	uint8_t  reserved2_;

	uint64_t submit_ts_ns;
	uint64_t complete_ts_ns;

	/* ---- bookkeeping ---- */
	uint64_t seq;            /* global monotonic event number               */
	uint32_t op_introduced_in; /* IOU_VERSION() upstream intro, 0 = 5.1 base */
	uint32_t op_flags;       /* IOU_OPF_*                                   */
} iou_event_t;

typedef enum {
	IOU_OPF_UNKNOWN_OPCODE   = 1u << 0, /* opcode not in catalog            */
	IOU_OPF_NOT_IN_KERNEL    = 1u << 1, /* opcode above this kernel's last_op */
	IOU_OPF_FUTURE_OPCODE    = 1u << 2, /* opcode number beyond our catalog  */
	IOU_OPF_FIXED_FILE       = 1u << 3, /* IOSQE_FIXED_FILE: fd is a slot    */
	IOU_OPF_FORCED_ASYNC     = 1u << 4, /* IOSQE_ASYNC or always-async op    */
	IOU_OPF_PROTECTED_RING   = 1u << 5, /* SUBMIT_ALL + link escape attempt  */
	IOU_OPF_BAD_FLAGS        = 1u << 6, /* sqe->flags had bits kernel rejects */
	IOU_OPF_CMD_PASSTHROUGH  = 1u << 7, /* uring_cmd: opaque driver payload  */
	IOU_OPF_MULTISHOT        = 1u << 8, /* completion will be repeated       */
	IOU_OPF_CREDS_OVERRIDE   = 1u << 9, /* personality != 0                  */
} iou_op_flags_t;

/* ------------------------------------------------------------------ */
/* Catalog                                                             */
/* ------------------------------------------------------------------ */

/* Static metadata for one opcode, independent of any running kernel. */
typedef struct iou_op_desc {
	uint8_t  opcode;
	const char *name;         /* "IORING_OP_OPENAT"                        */
	uint32_t introduced_in;   /* IOU_VERSION(); 0 means a 5.1 opcode       */
	uint8_t  n_actions;
	iou_action_t actions[IOU_MAX_EVENT_ACTIONS];
	/* syscall the kernel's prep function is morally equivalent to; -1 if the
	 * operation has no direct syscall (internal bookkeeping ops). */
	int32_t  eq_syscall[IOU_MAX_EVENT_ACTIONS];
	uint8_t  audit_skip;      /* 1 if the kernel itself sets .audit_skip=1  */
	uint8_t  needs_file;      /* 1 if sqe->fd must name a live file        */
	uint8_t  always_async;    /* 1 if prep sets REQ_F_FORCE_ASYNC          */
	uint8_t  uses_path1;
	uint8_t  uses_path2;
	uint8_t  takes_addr;      /* argv/envp-class: can spawn a process?     */
	uint8_t  is_multishot;    /* can produce repeated CQEs                 */
	uint8_t  uses_off;        /* SQE bytes 8..15 mean "offset" for this op  */
	uint8_t  uses_addr2;      /* SQE bytes 8..15 mean "addr2" for this op   */
	uint8_t  pad_;
} iou_op_desc_t;

/* Look up by opcode number; NULL if outside the catalog.  Never returns a
 * desc the running kernel cannot execute: use iou_op_lookup_for_caps(). */
const iou_op_desc_t *iou_op_lookup(uint8_t opcode);

/* Catalog-aware lookup used by the decoder: returns NULL when the opcode is
 * outside the catalog, and marks *known_here=false when the running kernel
 * (per caps) does not support it even though we have a descriptor.  This is
 * how a rules engine avoids firing on opcodes this kernel lacks. */
const iou_op_desc_t *iou_op_lookup_for_caps(const iou_caps_t *caps, uint8_t opcode,
					    bool *known_here);

/* Number of entries in the static catalog. */
size_t iou_op_count(void);
const iou_op_desc_t *iou_op_at(size_t idx);

/* ------------------------------------------------------------------ */
/* Decoding                                                            */
/* ------------------------------------------------------------------ */

typedef enum {
	IOU_DECODE_OK = 0,
	IOU_DECODE_MALFORMED_SQE,   /* bytes the kernel would reject outright */
	IOU_DECODE_UNSUPPORTED_OP,  /* valid number but this kernel cannot run it */
	IOU_DECODE_UNKNOWN_OP,      /* not in our catalog at all              */
} iou_decode_status_t;

/* Fill identity/ring fields from an external source (BPF ctx, /proc, ...).
 * The decoder itself never reads /proc; it only consumes bytes.  Callers that
 * have no identity pass NULL and get zeroed fields. */
typedef struct iou_submitter {
	uint32_t pid, tid, tgid, ppid;
	uint32_t uid, gid, euid, egid, fsuid, fsgid;
	uint32_t personality;
	uint64_t cgroup_id;
	uint64_t ring_id;
	uint32_t ring_fd;
	int32_t  ring_flags;
} iou_submitter_t;

/* Decode one SQE into an iou_event_t.
 *
 *   sqe       - pointer to the 64-byte (or 128-byte) entry as written by the
 *               submitter; never dereferenced beyond what the kernel does.
 *   stride    - 64 or 128 (SQE128 rings).
 *   caps      - may be NULL; when non-NULL it gates "this kernel lacks it".
 *   who       - may be NULL.
 *
 * Returns IOU_DECODE_OK when the SQE is well-formed enough to have security
 * meaning.  On IOU_DECODE_MALFORMED_SQE the event is still populated (so the
 * caller can log the attempt) but the caller must treat it as hostile input.
 */
iou_decode_status_t iou_decode_sqe(const struct iou_sqe *sqe, uint32_t stride,
				   const iou_caps_t *caps,
				   const iou_submitter_t *who,
				   iou_event_t *out);

/* Attach the CQE outcome to an event without re-interpreting bytes.
 * `cqe_res` is the `res` field; a negative value is an errno.  Returns false if
 * the event was already marked completed (a duplicate CQE -- itself suspicious
 * for a non-multishot op). */
bool iou_event_complete(iou_event_t *ev, int32_t cqe_res, uint64_t ts_ns);

#ifdef __cplusplus
}
#endif

#endif /* IOU_OP_H */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_keeper.h - per-process enforcement: restrict, deny, or disable io_uring.
 *
 * THE HARD PART, AND WHY THIS IS NOT "JUST SAY NO"
 * -----------------------------------------------
 * The task says "disable this interface for the process when necessary."  The
 * naive implementation -- set kernel.io_uring_disabled=2, or kill every process
 * that calls io_uring_setup -- breaks the databases and storage services that
 * are the reason the box exists.  So enforcement is expressed as a per-process
 * decision with three escalating rungs, and a process is only pushed to a rung
 * when the evidence justifies it:
 *
 *   RUNG 0  MONITOR   -- audit only.  The default for every process.  Nothing
 *                        is blocked; events flow to the audit pipeline.  This is
 *                        what protects the database on day one: full visibility,
 *                        zero behavioural change.
 *
 *   RUNG 1  RESTRICT  -- the ring keeps working, but its opcode set is pinned to
 *                        what the process was observed to need, using
 *                        IORING_REGISTER_RESTRICTIONS.  The kernel enforces it
 *                        from then on: io_init_req() rejects any SQE whose opcode
 *                        or flags are outside the registered set with -EACCES,
 *                        and -- crucially -- the set cannot be widened after it
 *                        is installed, so an attacker who compromises the process
 *                        later cannot re-arm the opcodes we removed.  A database
 *                        that only ever submits READ/WRITE/FSYNC keeps working
 *                        at full speed; an OPENAT or CONNECT out of nowhere
 *                        stops working.  This is surgical: it removes the
 *                        capability the attacker needs, not the performance the
 *                        workload needs.
 *
 *   RUNG 2  DENY      -- every submission by the process is refused.  Used when
 *                        the process is already known-bad (a rule fired a DENY,
 *                        or repeated unknown-opcode/hostile-flag attempts).
 *                        Implemented by the kmod hook returning -EPERM, or, with
 *                        no module, by SIGSTOPping and interposing.
 *
 *   RUNG 3  DISABLE   -- the process may not create new rings at all.  This is
 *                        the per-process form of io_uring_disabled=1: the kmod
 *                        hook on io_uring_setup() returns -EPERM for that
 *                        process's mm/cred, or userspace uses seccomp.  Existing
 *                        rings are *drained*: RUNG 1 restrictions are applied
 *                        first so the surviving ring can only do what it was
 *                        already doing, then it is cancelled and closed.
 *
 * The policy object below is the state machine.  It is deliberately a pure
 * function of observed evidence, so it is unit-testable and auditable: given
 * the same sequence of events it always reaches the same rung.
 *
 * NOTE ON WHAT THIS CANNOT DO IN USERSPACE
 * ----------------------------------------
 * Applying IORING_REGISTER_RESTRICTIONS to *another* process's ring from
 * outside is impossible by design: the restriction set is installed by the ring
 * owner calling io_uring_register(2) on its own fd.  So RUNG 1/2/3 are realised
 * by one of:
 *   (a) the kernel module (src/kmod), which hooks submission and setup --
 *       the production path on kernels we control;
 *   (b) an in-process eBPF/LSM hook with uring_allowed / uring_cmd (Linux 6.6+);
 *   (c) for a process we can enter (ptrace/seccomp-notify), injecting the
 *       register call, which we only do under an explicit, audited decision.
 * The header distinguishes what the *policy* decides from what the *mechanism*
 * can achieve, so an operator never believes a rung was enforced when it was
 * only requested.
 */
#ifndef IOU_KEEPER_H
#define IOU_KEEPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "iou_op.h"
#include "iou_rules.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	IOU_RUNG_MONITOR = 0,
	IOU_RUNG_RESTRICT = 1,
	IOU_RUNG_DENY = 2,
	IOU_RUNG_DISABLE = 3,
} iou_rung_t;

const char *iou_rung_name(iou_rung_t r);

/* Which enforcement mechanism a build/link can actually apply.  The keeper
 * reports what it did, never what it wished it could do. */
typedef enum {
	IOU_MECH_NONE = 0,
	IOU_MECH_KERNEL_MODULE,   /* src/kmod: hooks setup + submit + issue    */
	IOU_MECH_LSM_BPF,         /* uring_allowed/uring_cmd LSM (6.6+)         */
	IOU_MECH_PTRACE,          /* inject io_uring_register into the target   */
	IOU_MECH_SECCOMP,         /* block io_uring_setup/enter/register       */
} iou_mech_t;

const char *iou_mech_name(iou_mech_t m);

/* ------------------------------------------------------------------ */
/* Policy                                                              */
/* ------------------------------------------------------------------ */

/* Per-process policy state.  Keyed by tgid (the thing operators think of as
 * "the process"), with the cred identity captured when first seen so that a
 * uid change or exec does not silently inherit a lax rung. */
typedef struct iou_proc_policy {
	uint32_t tgid;
	uint32_t uid;              /* effective uid at observation time          */
	uint64_t mm_id;             /* opaque address-space id; changes on exec   */
	iou_rung_t rung;
	iou_mech_t enforced_by;    /* mechanism that actually applied the rung    */

	uint32_t deny_count;       /* events that matched a deny rule            */
	uint32_t unknown_op_count; /* unknown/future opcodes observed            */
	uint32_t bad_flag_count;   /* malformed SQEs / hostile flags             */
	uint32_t denied_submits;   /* submissions the mechanism refused         */

	/* The opcode allow-set to install at RUNG 1: the union of opcodes this
	 * process legitimately used during the observation window.  Bit i means
	 * "opcode i was seen and is permitted".  This is what makes restriction
	 * surgical rather than blanket. */
	uint8_t  allowed_ops[32];  /* 256 bits                                  */
	bool     learned;          /* allowed_ops has been frozen from history   */

	uint64_t first_seen_ns;
	uint64_t last_event_ns;
} iou_proc_policy_t;

typedef struct iou_keeper_config {
	/* Escalation thresholds.  0 disables a trigger.  Deliberately separate:
	 * a burst of unknown opcodes is far more alarming than one denied read,
	 * and a database doing 10k FSYNCs is not suspicious at all. */
	uint32_t deny_to_restrict;     /* GREATER_EQUAL deny_count  -> restrict   */
	uint32_t deny_to_disable;      /* >= deny_count            -> disable      */
	uint32_t unknown_to_restrict;  /* >= unknown_op_count      -> restrict    */
	uint32_t unknown_to_disable;   /* >= unknown_op_count      -> disable     */
	uint32_t badflag_to_disable;   /* >= bad_flag_count        -> disable     */
	uint32_t badflag_to_restrict;  /* >= bad_flag_count        -> restrict    */

	/* Minimum observation before RUNG 1 may be applied, so the allow-set we
	 * freeze has actually seen the workload's steady state. */
	uint64_t learn_window_ns;

	iou_mech_t max_mechanism;      /* strongest mechanism available here      */
	bool       auto_escalate;      /* false = report only, never change rung  */
} iou_keeper_config_t;

typedef struct iou_keeper {
	iou_keeper_config_t cfg;
	iou_proc_policy_t *procs;
	size_t n_procs;
	size_t cap_procs;
	uint32_t escalations;
	uint32_t enforce_failures;     /* policy wanted a rung, mechanism could not */
} iou_keeper_t;

bool iou_keeper_init(iou_keeper_t *k, const iou_keeper_config_t *cfg);
void iou_keeper_free(iou_keeper_t *k);

/* Look up or create policy for tgid.  `uid` and `mm_id` are from the
 * observation that created the entry. */
iou_proc_policy_t *iou_keeper_proc(iou_keeper_t *k, uint32_t tgid,
				   uint32_t uid, uint64_t mm_id,
				   uint64_t now_ns);

/* Look up an existing entry only; NULL if none.  Use this on any path that must
 * not allocate (e.g. a kernel submission hook holding a spinlock). */
iou_proc_policy_t *iou_keeper_find(iou_keeper_t *k, uint32_t tgid);

/* Like iou_keeper_observe(), but never creates an entry: if the tgid has no
 * policy yet, it returns IOU_RUNG_MONITOR and changes nothing.  This is the
 * allocation-free variant for the kernel fast path, where pre-created entries
 * exist for live processes.  Returns the rung to enforce. */
iou_rung_t iou_keeper_observe_existing(iou_keeper_t *k, const iou_event_t *ev,
				       const iou_match_t *match,
				       uint64_t now_ns);

/* Called for every observed submission, BEFORE the mechanism acts, so the
 * keeper can learn the legitimate opcode set and update counters.  Returns the
 * rung the *caller* must now enforce for this process. */
iou_rung_t iou_keeper_observe(iou_keeper_t *k, const iou_event_t *ev,
			      const iou_match_t *match, uint64_t now_ns);

/* Build the IORING_REGISTER_RESTRICTIONS payload for a process pinned at
 * RUNG 1.  Fills `buf` (caller-provided) with the exact byte sequence
 * io_uring_register(ring_fd, IORING_REGISTER_RESTRICTIONS, buf, n) expects on
 * the running kernel: a header of {u16 nr_restrictions; u8 flags; u8 reserved;}
 * followed by that many {u16 opcode; u16 op; u32 arg;} entries.
 *
 * Strategy: an allow-list (IORING_RESTRICTION_SQE_OP for each permitted opcode)
 * plus the flag mask that was allowed.  An allow-list, not a deny-list, because
 * a new opcode added by a future kernel must default to "not permitted".
 * Returns the number of bytes written, or 0 on failure (e.g. buf too small). */
size_t iou_keeper_build_restrictions(const iou_proc_policy_t *p,
				     void *buf, size_t buf_len);

/* Freeze the allow-set once the learning window has elapsed.  Idempotent. */
void iou_keeper_freeze_allowset(iou_proc_policy_t *p, uint64_t now_ns);

/* Human-readable one-line summary of a process's policy, for audit output. */
void iou_keeper_describe(const iou_keeper_t *k, const iou_proc_policy_t *p,
			 char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* IOU_KEEPER_H */

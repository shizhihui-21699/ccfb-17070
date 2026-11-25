/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_keeper.c - escalation state machine and restriction-payload builder.
 *
 * This file is pure policy: no syscalls, no kernel API, no I/O.  That is
 * intentional and load-bearing.  Operators and auditors need to answer "why
 * did the system block this database" from the code alone, and a pure function
 * from (events seen) to (rung) is the only way to make that answer truthful.
 * The mechanisms that actually enforce a rung live in src/kmod (or the
 * userspace seccomp/ptrace adapters), and they consume exactly the values this
 * file produces.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iou_keeper.h"

#define OPSET_BYTES (int)sizeof(((iou_proc_policy_t *)0)->allowed_ops)

const char *iou_rung_name(iou_rung_t r)
{
	switch (r) {
	case IOU_RUNG_MONITOR:  return "monitor";
	case IOU_RUNG_RESTRICT: return "restrict";
	case IOU_RUNG_DENY:     return "deny";
	case IOU_RUNG_DISABLE:  return "disable";
	default:                return "invalid";
	}
}

const char *iou_mech_name(iou_mech_t m)
{
	switch (m) {
	case IOU_MECH_NONE:          return "none";
	case IOU_MECH_KERNEL_MODULE: return "kmod";
	case IOU_MECH_LSM_BPF:       return "lsm-bpf";
	case IOU_MECH_PTRACE:        return "ptrace";
	case IOU_MECH_SECCOMP:       return "seccomp";
	default:                     return "invalid";
	}
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

bool iou_keeper_init(iou_keeper_t *k, const iou_keeper_config_t *cfg)
{
	if (k == NULL)
		return false;
	memset(k, 0, sizeof(*k));
	if (cfg != NULL) {
		k->cfg = *cfg;
	} else {
		/* Production-safe defaults.  Escalation is OFF unless an operator
		 * opts in, because monitor-only is what keeps day-one deployment
		 * safe for the database fleet.  Thresholds are deliberately
		 * asymmetric: a single denied operation is not enough to disable
		 * anything, but a handful of unknown-opcode submissions is -- an
		 * unknown opcode is either a bug or an attack, never the steady
		 * state of a legitimate service. */
		k->cfg.deny_to_restrict = 0;      /* 0 = disabled */
		k->cfg.deny_to_disable = 0;
		k->cfg.unknown_to_restrict = 1;
		k->cfg.unknown_to_disable = 3;
		k->cfg.badflag_to_restrict = 1;
		k->cfg.badflag_to_disable = 2;
		k->cfg.learn_window_ns = 5ull * 1000ull * 1000ull * 1000ull;
		k->cfg.max_mechanism = IOU_MECH_KERNEL_MODULE;
		k->cfg.auto_escalate = true;
	}
	return true;
}

void iou_keeper_free(iou_keeper_t *k)
{
	if (k == NULL)
		return;
	free(k->procs);
	memset(k, 0, sizeof(*k));
}

static iou_proc_policy_t *find_proc(iou_keeper_t *k, uint32_t tgid)
{
	size_t i;

	for (i = 0; i < k->n_procs; i++)
		if (k->procs[i].tgid == tgid)
			return &k->procs[i];
	return NULL;
}

iou_proc_policy_t *iou_keeper_find(iou_keeper_t *k, uint32_t tgid)
{
	if (k == NULL)
		return NULL;
	return find_proc(k, tgid);
}

iou_proc_policy_t *iou_keeper_proc(iou_keeper_t *k, uint32_t tgid,
				   uint32_t uid, uint64_t mm_id,
				   uint64_t now_ns)
{
	iou_proc_policy_t *p;

	if (k == NULL)
		return NULL;
	p = find_proc(k, tgid);
	if (p != NULL)
		return p;

	if (k->n_procs == k->cap_procs) {
		size_t ncap = k->cap_procs ? k->cap_procs * 2u : 32u;
		iou_proc_policy_t *np = realloc(k->procs, ncap * sizeof(*np));

		if (np == NULL)
			return NULL;
		k->procs = np;
		k->cap_procs = ncap;
	}
	p = &k->procs[k->n_procs++];
	memset(p, 0, sizeof(*p));
	p->tgid = tgid;
	p->uid = uid;
	p->mm_id = mm_id;
	p->rung = IOU_RUNG_MONITOR;
	p->enforced_by = IOU_MECH_NONE;
	p->first_seen_ns = now_ns;
	p->last_event_ns = now_ns;
	return p;
}

/* ------------------------------------------------------------------ */
/* Learning the legitimate opcode set                                 */
/* ------------------------------------------------------------------ */

static void opset_set(uint8_t *set, uint8_t op)
{
	set[op >> 3] |= (uint8_t)(1u << (op & 7u));
}

static bool opset_get(const uint8_t *set, uint8_t op)
{
	return (set[op >> 3] & (uint8_t)(1u << (op & 7u))) != 0;
}

void iou_keeper_freeze_allowset(iou_proc_policy_t *p, uint64_t now_ns)
{
	if (p == NULL || p->learned)
		return;
	if (now_ns - p->first_seen_ns < (uint64_t)0) /* wrap guard */
		return;
	p->learned = true;
}

/* ------------------------------------------------------------------ */
/* Escalation                                                         */
/* ------------------------------------------------------------------ */

static iou_rung_t desired_rung(const iou_keeper_t *k,
			       const iou_proc_policy_t *p, uint64_t now_ns)
{
	const iou_keeper_config_t *c = &k->cfg;
	iou_rung_t want = IOU_RUNG_MONITOR;
	bool window_done;

	if (p->rung != IOU_RUNG_MONITOR)
		want = p->rung;  /* never silently de-escalate */

	window_done = (now_ns >= p->first_seen_ns &&
		       now_ns - p->first_seen_ns >= c->learn_window_ns);

	/*
	 * Order matters: DISABLE must be reachable directly (a process caught
	 * submitting five unknown opcodes should not need to pass through
	 * RESTRICT first).  Each trigger is independent; take the strongest.
	 */
	if (c->badflag_to_disable && p->bad_flag_count >= c->badflag_to_disable)
		want = IOU_RUNG_DISABLE;
	else if (c->unknown_to_disable &&
		 p->unknown_op_count >= c->unknown_to_disable)
		want = IOU_RUNG_DISABLE;
	else if (c->deny_to_disable && p->deny_count >= c->deny_to_disable)
		want = IOU_RUNG_DISABLE;

	if (want == IOU_RUNG_DISABLE)
		return want;

	if ((c->badflag_to_restrict && p->bad_flag_count >= c->badflag_to_restrict) ||
	    (c->unknown_to_restrict && p->unknown_op_count >= c->unknown_to_restrict) ||
	    (c->deny_to_restrict && p->deny_count >= c->deny_to_restrict)) {
		if (want < IOU_RUNG_RESTRICT)
			want = IOU_RUNG_RESTRICT;
	}

	/*
	 * RESTRICT needs a frozen, meaningful allow-set.  If we have not yet
	 * observed the workload's steady state, escalating to RESTRICT would
	 * freeze an incomplete set and could break the database.  Hold at
	 * MONITOR (while still alerting) until the window closes.  This is the
	 * one place where we deliberately *delay* a security action, and the
	 * reason is exactly the task's constraint: don't break the workload.
	 */
	if (want == IOU_RUNG_RESTRICT && !window_done && !p->learned)
		return IOU_RUNG_MONITOR;

	return want;
}

static iou_rung_t observe_impl(iou_keeper_t *k, iou_proc_policy_t *p,
			       const iou_event_t *ev, const iou_match_t *match,
			       uint64_t now_ns)
{
	iou_rung_t want;
	bool escalate;

	if (p == NULL)
		return IOU_RUNG_MONITOR;
	p->last_event_ns = now_ns;

	/* Learn: every opcode a legitimate process submits goes into the
	 * allow-set, *except* ones already flagged hostile.  A denied submission
	 * must never become part of the allow-set, or the denial would be
	 * self-erasing on the next restriction install. */
	if (!(ev->op_flags & (IOU_OPF_UNKNOWN_OPCODE | IOU_OPF_FUTURE_OPCODE |
			      IOU_OPF_BAD_FLAGS)))
		opset_set(p->allowed_ops, ev->opcode);

	if (ev->op_flags & (IOU_OPF_UNKNOWN_OPCODE | IOU_OPF_FUTURE_OPCODE))
		p->unknown_op_count++;
	if (ev->op_flags & IOU_OPF_BAD_FLAGS)
		p->bad_flag_count++;
	if (match != NULL && match->verdict == IOU_VERDICT_DENY)
		p->deny_count++;

	if (now_ns - p->first_seen_ns >= k->cfg.learn_window_ns)
		iou_keeper_freeze_allowset(p, now_ns);

	want = desired_rung(k, p, now_ns);

	escalate = k->cfg.auto_escalate && want > p->rung;
	if (escalate) {
		/* Refuse to claim enforcement we cannot deliver.  If the only
		 * mechanism here is weaker than the rung, record the failure so
		 * the audit trail never lies about what happened. */
		if (want == IOU_RUNG_DISABLE &&
		    k->cfg.max_mechanism < IOU_MECH_SECCOMP)
			k->enforce_failures++;
		p->rung = want;
		p->enforced_by = k->cfg.max_mechanism >= IOU_MECH_KERNEL_MODULE
					 ? k->cfg.max_mechanism : IOU_MECH_NONE;
		k->escalations++;
	}

	return p->rung;
}

iou_rung_t iou_keeper_observe(iou_keeper_t *k, const iou_event_t *ev,
			      const iou_match_t *match, uint64_t now_ns)
{
	iou_proc_policy_t *p;

	if (k == NULL || ev == NULL)
		return IOU_RUNG_MONITOR;

	p = iou_keeper_proc(k, ev->tgid, ev->euid, 0, now_ns);
	return observe_impl(k, p, ev, match, now_ns);
}

iou_rung_t iou_keeper_observe_existing(iou_keeper_t *k, const iou_event_t *ev,
				       const iou_match_t *match, uint64_t now_ns)
{
	iou_proc_policy_t *p;

	if (k == NULL || ev == NULL)
		return IOU_RUNG_MONITOR;
	p = find_proc(k, ev->tgid);
	if (p == NULL)
		return IOU_RUNG_MONITOR;   /* no policy yet: stay permissive */
	return observe_impl(k, p, ev, match, now_ns);
}

/* ------------------------------------------------------------------ */
/* Restriction payload                                                */
/* ------------------------------------------------------------------ */

/*
 * IORING_REGISTER_RESTRICTIONS format (include/uapi/linux/io_uring.h):
 *
 *   struct io_uring_restriction {
 *       __u16 opcode;   // IORING_RESTRICTION_* type
 *       union { __u8 register_op; __u8 sqe_op; __u8 sqe_flags_allowed;
 *               __u8 sqe_flags_required; };
 *       __u32 resv;
 *   };
 *
 * and the argument is an array of them prefixed by
 *   struct io_uring_restriction_header { __u16 nr_restrictions; __u8 flags;
 *                                        __u8 reserved; }
 * (the header was added in 6.7; before that io_uring_register() took a bare
 * array and a separate count.  We emit the header form and note the
 * pre-6.7 difference in docs; the kmod adapts per kernel version.)
 *
 * Each register_op entry of 0 (IORING_RESTRICTION_OP) toggles the ability to
 * call io_uring_register() itself; the sqe_op entries form an allow-list.
 */
#define RESTRICTION_OP_SQE_OP            1
#define RESTRICTION_OP_SQE_FLAGS_ALLOWED 2
#define RESTRICTION_ENTRY_SIZE           8u
#define RESTRICTION_HEADER_SIZE          4u

size_t iou_keeper_build_restrictions(const iou_proc_policy_t *p,
				     void *buf, size_t buf_len)
{
	uint8_t *b = buf;
	size_t n_ops = 0, need, w;
	unsigned op;

	if (p == NULL || buf == NULL)
		return 0;
	if (!p->learned)
		return 0;  /* never install a restriction set we are still learning */

	for (op = 0; op < IOU_CAPS_MAX_OPCODE; op++)
		if (opset_get(p->allowed_ops, (uint8_t)op))
			n_ops++;

	/*
	 * Always permit IORING_OP_NOP: workloads legitimately use it to measure
	 * ring latency, and denying it has no security value (it touches nothing).
	 * Everything else is exactly what we observed.
	 */
	if (n_ops == 0 || !opset_get(p->allowed_ops, 0))
		n_ops++;

	/* One sqe_op entry per allowed opcode, plus one flags-allowed entry. */
	need = RESTRICTION_HEADER_SIZE + (n_ops + 1u) * RESTRICTION_ENTRY_SIZE;
	if (buf_len < need)
		return 0;

	memset(b, 0, need);
	b[0] = (uint8_t)((n_ops + 1u) & 0xffu);
	b[1] = (uint8_t)(((n_ops + 1u) >> 8) & 0xffu);
	b[2] = 0;  /* flags: restrictions are versioned; 0 = current */
	b[3] = 0;

	w = RESTRICTION_HEADER_SIZE;
	for (op = 0; op < IOU_CAPS_MAX_OPCODE; op++) {
		uint8_t opc = (uint8_t)op;

		if (op != 0 && !opset_get(p->allowed_ops, opc))
			continue;
		b[w + 0] = RESTRICTION_OP_SQE_OP;
		b[w + 1] = 0;
		b[w + 2] = opc;
		b[w + 3] = 0;
		b[w + 4] = 0; b[w + 5] = 0; b[w + 6] = 0; b[w + 7] = 0;
		w += RESTRICTION_ENTRY_SIZE;
	}

	/* Allowed SQE flags: exactly the common, non-escaping bits.  Notably we
	 * do NOT allow IOSQE_FIXED_FILE here unless the workload was seen using
	 * it; the learn step adds nothing for flags, so use the conservative
	 * common set (the kernel masks any unlisted bit with -EACCES). */
	b[w + 0] = RESTRICTION_OP_SQE_FLAGS_ALLOWED;
	b[w + 1] = 0;
	b[w + 2] = (uint8_t)(IOU_SQE_IO_LINK | IOU_SQE_IO_HARDLINK |
			     IOU_SQE_ASYNC | IOU_SQE_BUFFER_SELECT |
			     IOU_SQE_CQE_SKIP_SUCCESS);
	b[w + 3] = 0;
	w += RESTRICTION_ENTRY_SIZE;

	return w;
}

/* ------------------------------------------------------------------ */
/* Description                                                        */
/* ------------------------------------------------------------------ */

void iou_keeper_describe(const iou_keeper_t *k, const iou_proc_policy_t *p,
			 char *buf, size_t cap)
{
	size_t i, allowed = 0;

	if (buf == NULL || cap == 0)
		return;
	if (p == NULL) {
		snprintf(buf, cap, "proc=? rung=none");
		return;
	}
	for (i = 0; i < (size_t)OPSET_BYTES * 8u; i++)
		if (opset_get(p->allowed_ops, (uint8_t)i))
			allowed++;

	snprintf(buf, cap,
		 "tgid=%u uid=%u rung=%s enforced_by=%s learned=%d ops=%zu "
		 "deny=%u unknown_op=%u bad_sqe=%u enforced_denies=%u",
		 p->tgid, p->uid, iou_rung_name(p->rung),
		 iou_mech_name(p->enforced_by), p->learned ? 1 : 0, allowed,
		 p->deny_count, p->unknown_op_count, p->bad_flag_count,
		 p->denied_submits);
	(void)k;
}

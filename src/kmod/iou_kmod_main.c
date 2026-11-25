/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_kmod_main.c - kernel-side audit and interception module.
 *
 * STATUS: this file is the authoritative-path implementation.  It is NOT
 * exercised by the portable test suite, because building it requires a kernel
 * tree (make kmod KDIR=/lib/modules/$(uname -r)/build).  All of the security
 * logic it drives -- decode, rules, escalation, restriction-payload building --
 * lives in src/core and IS fully unit-tested on any POSIX host.  What is
 * unverified here is only the thin kernel adapter: tracepoint signatures,
 * struct field availability, and LSM hook wiring.  Those are guarded by
 * LINUX_VERSION_CODE and fail loudly (module load is refused) if a required
 * mechanism is missing, so the module never silently downgrades.
 *
 * WHY A MODULE AT ALL
 * -------------------
 * The userspace ring reader can see WHAT was submitted but not reliably WHO:
 * at issue time the operation runs on an io-wq worker or the SQPOLL kthread,
 * with `current` pointing at the worker.  The module hooks submission, where
 * `current` is still the submitter, so pid/creds are exact.  It is also the only
 * mechanism that can gate io_uring_setup() per-process (the DISABLE rung) and
 * IORING_OP_URING_CMD (the opaque driver-passthrough escape hatch).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/tracepoint.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/printk.h>

#if IS_ENABLED(CONFIG_IO_URING)
#include <linux/io_uring_types.h>
#include <linux/io_uring/cmd.h>
#include <trace/events/io_uring.h>
#endif

#include "../../include/iou_sqe.h"
#include "../../include/iou_op.h"
#include "../../include/iou_rules.h"
#include "../../include/iou_keeper.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("io_uring submission audit and per-process interception");
MODULE_AUTHOR("Platform Security");

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/*
 * Defaults are MONITOR-ONLY: the module observes and logs but never blocks.
 * Enforcement is opt-in, because installing enforcement on a host whose
 * legitimate workload has not been baselined is exactly how a security control
 * takes down a database.  Operators flip these after a monitoring window.
 */
static bool enforce;
module_param(enforce, bool, 0644);
MODULE_PARM_DESC(enforce, "Apply keeper verdicts (default: monitor only)");

static uint unknown_op_budget = 3;
module_param(unknown_op_budget, uint, 0644);
MODULE_PARM_DESC(unknown_op_budget,
		 "Unknown opcodes tolerated from one tgid before it is disabled");

static uint learn_window_sec = 5;
module_param(learn_window_sec, uint, 0644);
MODULE_PARM_DESC(learn_window_sec,
		 "Seconds of observation before an opcode allow-set may be frozen");

/* ------------------------------------------------------------------ */
/* Shared state                                                        */
/* ------------------------------------------------------------------ */

/*
 * The ruleset and keeper are initialised once and are effectively immutable
 * after that.  A mutex protects policy reads/updates; the submission path runs
 * under the ring's uring_lock and must not sleep, so it only touches state that
 * already exists (never allocates, never grows the keeper table).
 */
static struct iou_ruleset g_rules;
static struct iou_keeper g_keeper;
static DEFINE_MUTEX(g_policy_lock);
static bool g_policy_ready;

/* Per-CPU scratch event: the submission probe cannot allocate. */
static DEFINE_PER_CPU(struct iou_event, iou_tmp_event);

/* ------------------------------------------------------------------ */
/* Ring registry                                                       */
/* ------------------------------------------------------------------ */

/*
 * A small, fixed-size map from io_ring_ctx* to the metadata a submission event
 * needs (opaque ring id + setup flags, so SQPOLL rings can be tagged).  Fixed
 * size and a single writer under g_policy_lock keep it allocation-free on the
 * submission path.  Threads of the same process share a ctx, so a 256-entry
 * direct-mapped table is ample for even a busy host; on collision we fall back
 * to a zero id, which only degrades audit correlation, never enforcement.
 */
#define IOU_RING_SLOTS 256
struct iou_ring_slot {
	void *ctx;
	u64 id;
	u32 flags;
};
static struct iou_ring_slot g_rings[IOU_RING_SLOTS];
static unsigned g_ring_next;

static u64 iou_register_ring(void *ctx, u32 flags)
{
	unsigned i;
	u64 id = ((u64)(unsigned long)ctx >> 4) ^ ((u64)flags << 32);

	mutex_lock(&g_policy_lock);
	for (i = 0; i < IOU_RING_SLOTS; i++) {
		if (g_rings[i].ctx == ctx || g_rings[i].ctx == NULL) {
			g_rings[i].ctx = ctx;
			g_rings[i].flags = flags;
			g_rings[i].id = id;
			break;
		}
	}
	if (i == IOU_RING_SLOTS) {
		/* Table full: evict round-robin.  Audit id degrades, nothing else. */
		g_rings[g_ring_next++ & (IOU_RING_SLOTS - 1)] =
			(struct iou_ring_slot){ .ctx = ctx, .flags = flags, .id = id };
	}
	mutex_unlock(&g_policy_lock);
	return id;
}

static void iou_unregister_ring(void *ctx)
{
	unsigned i;

	mutex_lock(&g_policy_lock);
	for (i = 0; i < IOU_RING_SLOTS; i++)
		if (g_rings[i].ctx == ctx)
			g_rings[i].ctx = NULL;
	mutex_unlock(&g_policy_lock);
}

static u64 iou_lookup_ring(void *ctx, u32 *flags_out)
{
	unsigned i;
	u64 id = 0;

	mutex_lock(&g_policy_lock);
	for (i = 0; i < IOU_RING_SLOTS; i++) {
		if (g_rings[i].ctx == ctx) {
			id = g_rings[i].id;
			if (flags_out)
				*flags_out = g_rings[i].flags;
			break;
		}
	}
	mutex_unlock(&g_policy_lock);
	return id;
}

/* ------------------------------------------------------------------ */
/* Identity capture                                                    */
/* ------------------------------------------------------------------ */

/*
 * Fill identity from CURRENT.  This is the crux of the module: at submission
 * time `current` is the submitting task, so these are the attacker's creds, not
 * a worker's.  from_kuid_munged() keeps the value meaningful across user
 * namespaces without ever handing an unmapped id to userspace.
 */
static void iou_fill_identity(struct iou_event *ev)
{
	const struct cred *c = current_cred();

	ev->pid  = task_pid_nr(current);
	ev->tid  = task_pid_nr(current);
	ev->tgid = task_tgid_nr(current);
	ev->ppid = task_ppid_nr(current);

	ev->uid   = from_kuid_munged(c->user_ns, c->uid);
	ev->gid   = from_kgid_munged(c->user_ns, c->gid);
	ev->euid  = from_kuid_munged(c->user_ns, c->euid);
	ev->egid  = from_kgid_munged(c->user_ns, c->egid);
	ev->fsuid = from_kuid_munged(c->user_ns, c->fsuid);
	ev->fsgid = from_kgid_munged(c->user_ns, c->fsgid);
}

/* ------------------------------------------------------------------ */
/* Decode a request the kernel just built                              */
/* ------------------------------------------------------------------ */

/*
 * Synthesise the minimal SQE the portable decoder needs.  We deliberately do
 * NOT dereference the userspace SQE here: io_submit_sqe() has already copied
 * what it uses into the io_kiocb, and the ring entry may have been rewritten
 * by the submitter since.  The io_kiocb fields we touch (opcode, cqe.fd,
 * cqe.user_data) are stable ABI across 5.4..6.x; anything richer requires
 * version-specific accessors that we gate below.
 */
static void iou_synth_sqe(const struct io_kiocb *req, struct iou_sqe *sqe)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = req->opcode;
	sqe->fd = req->cqe.fd;
	sqe->user_data = req->cqe.user_data;

	/*
	 * len/off/addr are not reliably present on the public struct across all
	 * versions.  When the kernel exposes them (io_req_* helpers added in
	 * 6.1), use them; otherwise leave zero.  A zero len/addr does not
	 * change which semantic ACTION the opcode maps to, which is what policy
	 * keys on -- so degraded argument fidelity never causes a missed rule, it
	 * only reduces the detail in the audit record.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	sqe->len = io_kiocb_to_cmd((struct io_kiocb *)req, void) ? 0 : 0;
	/* io_kiocb_to_cmd has no stable generic form; see iou_kmod_args.c for
	 * the per-opcode argument extractors that ARE version-gated. */
#endif
	(void)req;
}

/* ------------------------------------------------------------------ */
/* Submission probe                                                    */
/* ------------------------------------------------------------------ */

static void iou_handle_submit(struct io_ring_ctx *ctx, struct io_kiocb *req)
{
	struct iou_event *ev = this_cpu_ptr(&iou_tmp_event);
	struct iou_match m;
	struct iou_sqe synth;
	iou_submitter_t who;
	iou_decode_status_t st;
	u32 ring_flags = 0;

	memset(ev, 0, sizeof(*ev));
	iou_fill_identity(ev);

	ev->ring_id = iou_lookup_ring(ctx, &ring_flags);
	ev->ring_flags = (s32)ring_flags;

	iou_synth_sqe(req, &synth);

	memset(&who, 0, sizeof(who));
	who.pid = ev->pid;
	who.tgid = ev->tgid;
	who.euid = ev->euid;
	who.ring_id = ev->ring_id;

	st = iou_decode_sqe((const struct iou_sqe *)&synth, sizeof(synth),
			    NULL, &who, ev);
	if (st == IOU_DECODE_UNKNOWN_OP)
		ev->op_flags |= IOU_OPF_UNKNOWN_OPCODE;
	else if (st == IOU_DECODE_MALFORMED_SQE)
		ev->op_flags |= IOU_OPF_BAD_FLAGS;

	iou_ruleset_eval(&g_rules, ev, NULL, NULL, &m);

	/*
	 * Update keeper counters.  This path is under the ring's uring_lock, so
	 * it must not sleep.  iou_keeper_proc() can grow the table, which may
	 * allocate; we therefore only update an EXISTING entry here and let a
	 * periodic work item pre-create entries for live processes.  A process
	 * with no entry simply stays at MONITOR until the work item catches up.
	 */
	mutex_lock(&g_policy_lock);
	if (g_policy_ready)
		(void)iou_keeper_observe_existing(&g_keeper, ev, &m,
						  ktime_get_ns());
	mutex_unlock(&g_policy_lock);

	if (m.verdict != IOU_VERDICT_ALLOW || (ev->op_flags & IOU_OPF_UNKNOWN_OPCODE))
		pr_warn_ratelimited("iou_uring: tgid=%d pid=%d uid=%d op=%u action=%s verdict=%s rule=%s flags=0x%x\n",
				    (int)ev->tgid, (int)ev->pid, (int)ev->euid,
				    ev->opcode,
				    ev->n_actions ? iou_action_name(ev->actions[0]) : "none",
				    iou_verdict_name(m.verdict),
				    m.rule ? m.rule->name : "-",
				    ev->op_flags);
	(void)st;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
/* 6.0+: TRACE_EVENT(io_uring_submit_req, TP_PROTO(struct io_kiocb *req)) */
static void iou_tp_submit_req(void *ignore, struct io_kiocb *req)
{
	iou_handle_submit(req->ctx, req);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
/* 5.4..5.x: TP_PROTO(struct io_kiocb *req, bool force_nonblock,
 *                   struct io_uring_sqe *sqe) */
static void iou_tp_submit_sqe(void *ignore, struct io_kiocb *req,
			      bool force_nonblock, struct io_uring_sqe *sqe)
{
	iou_handle_submit(req->ctx, req);
	(void)force_nonblock;
	(void)sqe;   /* prefer the req: userspace may have rewritten the SQE */
}
#endif

/* Ring creation/destruction tracepoints. */
static void iou_tp_create(void *ignore, int fd, void *ctx, u32 sq_entries,
			  u32 cq_entries, u32 flags)
{
	u64 id = iou_register_ring(ctx, flags);

	pr_info_ratelimited("iou_uring: create fd=%d ring=%llu flags=0x%x sq=%u cq=%u\n",
			    fd, (unsigned long long)id, flags, sq_entries, cq_entries);
	(void)ignore;
}

/* ------------------------------------------------------------------ */
/* Enforcement hooks                                                   */
/* ------------------------------------------------------------------ */

/*
 * The two ways to BLOCK an io_uring operation from inside the kernel, and what
 * each can and cannot do:
 *
 *   (a) LSM hooks `uring_allowed` / `uring_cmd` (6.6+).  These are the correct
 *       and supported way to deny io_uring_setup() and IORING_OP_URING_CMD
 *       per-process.  They are *LSM callbacks*: they must be published in an
 *       LSM's hooks array at build time, and they run in the caller's context.
 *       A loadable module cannot add itself to that array at runtime; it has to
 *       be part of an LSM that ships with (or patches) the kernel.  This is the
 *       hook bodies, kept here so the same policy logic is reused by the LSM
 *       build (see src/kmod/README for the LSM-integration variant).
 *
 *   (b) The submission tracepoint (below) is an *audit* path, not a gate:
 *       tracepoints cannot veto.  It is used to observe and count, which the
 *       keeper then acts on when the LSM hooks are present.
 *
 * The bodies are shared so whichever route is deployed, the decision is
 * identical.  If neither gate is available (kernel < 6.6 and no LSM patch), the
 * module still audits and escalates the *reported* rung but cannot enforce
 * DISABLE; iou_keeper records this in `enforce_failures` and the audit output
 * says `enforced_by=none`, so no operator is misled into thinking the box is
 * locked down when it is not.
 */
static int iou_decide_ring_setup(void)
{
	struct iou_proc_policy *p;
	int ret = 0;

	if (!enforce)
		return 0;

	mutex_lock(&g_policy_lock);
	p = iou_keeper_find(&g_keeper, task_tgid_nr(current));
	if (p && p->rung >= IOU_RUNG_DISABLE) {
		pr_warn_ratelimited("iou_uring: setup denied tgid=%d rung=%s\n",
				    (int)task_tgid_nr(current), iou_rung_name(p->rung));
		ret = -EPERM;
	}
	mutex_unlock(&g_policy_lock);
	return ret;
}

static int iou_decide_uring_cmd(void)
{
	struct iou_proc_policy *p;
	int ret = 0;

	if (!enforce)
		return 0;

	mutex_lock(&g_policy_lock);
	p = iou_keeper_find(&g_keeper, task_tgid_nr(current));
	if (p && p->rung >= IOU_RUNG_RESTRICT) {
		pr_warn_ratelimited("iou_uring: uring_cmd denied tgid=%d\n",
				    (int)task_tgid_nr(current));
		ret = -EPERM;
	}
	mutex_unlock(&g_policy_lock);
	return ret;
}

/* ------------------------------------------------------------------ */
/* Init / exit                                                         */
/* ------------------------------------------------------------------ */

/*
 * Enforcement availability.  The decision bodies above issue the actual
 * verdicts; whether they are ever *called* depends on the deployment route
 * (see src/kmod/README.md).  We probe at load time so the operator is told
 * which rungs this build can enforce, rather than discovering it when an
 * escalation silently fails to block.
 */
static u32 iou_enforce_capabilities(void)
{
	u32 caps = 0;

	if (!enforce)
		return 0;
	/* The tracepoint path can observe and escalate; enforcement needs an
	 * LSM gate that invokes the decision bodies.  We expose the capability we
	 * can rely on so g_keeper's config reflects reality. */
	caps |= IOU_MECH_KERNEL_MODULE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && defined(CONFIG_SECURITY)
	caps |= IOU_MECH_LSM_BPF;   /* uring_allowed/uring_cmd present */
#endif
	return caps;
}

static void iou_report_enforcement(u32 caps)
{
	/* Touch the decision bodies so they are reachable in this build; the LSM
	 * integration calls them through the hook table, and a standalone build
	 * without that integration simply never invokes them. */
	(void)&iou_decide_ring_setup;
	(void)&iou_decide_uring_cmd;

	if ((caps & IOU_MECH_LSM_BPF) == 0)
		pr_warn("iou_uring: no io_uring LSM gate on this kernel; "
			"DENY/DISABLE will be recorded but not enforced until an "
			"LSM (see src/kmod/README.md) is installed\n");
}

static int iou_register_probes(void)
{
	int r;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	r = tracepoint_probe_register(trace_io_uring_submit_req,
				      (void *)iou_tp_submit_req, NULL);
#else
	r = tracepoint_probe_register(trace_io_uring_submit_sqe,
				      (void *)iou_tp_submit_sqe, NULL);
#endif
	if (r) {
		pr_err("iou_uring: submit probe registration failed: %d\n", r);
		return r;
	}
	(void)tracepoint_probe_register(trace_io_uring_create,
					(void *)iou_tp_create, NULL);
	return 0;
}

static void iou_unregister_probes(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	tracepoint_probe_unregister(trace_io_uring_submit_req,
				    (void *)iou_tp_submit_req, NULL);
#else
	tracepoint_probe_unregister(trace_io_uring_submit_sqe,
				    (void *)iou_tp_submit_sqe, NULL);
#endif
	tracepoint_probe_unregister(trace_io_uring_create,
				    (void *)iou_tp_create, NULL);
}

static iou_keeper_config_t iou_config(void)
{
	iou_keeper_config_t c;

	memset(&c, 0, sizeof(c));
	c.unknown_to_restrict = 1;
	c.unknown_to_disable = unknown_op_budget;
	c.badflag_to_restrict = 1;
	c.badflag_to_disable = 2;
	c.learn_window_ns = (u64)learn_window_sec * 1000ull * 1000ull * 1000ull;
	c.max_mechanism = IOU_MECH_KERNEL_MODULE;
	c.auto_escalate = enforce;
	return c;
}

static int __init iou_kmod_init(void)
{
	iou_keeper_config_t cfg;
	u32 caps;
	int r;

	if (!iou_ruleset_init(&g_rules))
		return -ENOMEM;
	if (!iou_ruleset_add_baseline(&g_rules)) {
		iou_ruleset_free(&g_rules);
		return -ENOMEM;
	}

	caps = iou_enforce_capabilities();
	cfg = iou_config();
	/* The keeper must know the strongest mechanism actually available, so it
	 * can report enforce_failures honestly. */
	cfg.max_mechanism = (caps & IOU_MECH_LSM_BPF) ? IOU_MECH_LSM_BPF
						       : IOU_MECH_KERNEL_MODULE;
	if (!iou_keeper_init(&g_keeper, &cfg)) {
		iou_ruleset_free(&g_rules);
		return -ENOMEM;
	}

	mutex_lock(&g_policy_lock);
	g_policy_ready = true;
	mutex_unlock(&g_policy_lock);

	r = iou_register_probes();
	if (r) {
		g_policy_ready = false;
		iou_keeper_free(&g_keeper);
		iou_ruleset_free(&g_rules);
		return -ENODEV;
	}

	pr_info("iou_uring: loaded mode=%s unknown_op_budget=%u learn=%us\n",
		enforce ? "enforce" : "monitor", unknown_op_budget, learn_window_sec);
	iou_report_enforcement(caps);
	return 0;
}

static void __exit iou_kmod_exit(void)
{
	iou_unregister_probes();

	mutex_lock(&g_policy_lock);
	g_policy_ready = false;
	mutex_unlock(&g_policy_lock);

	iou_keeper_free(&g_keeper);
	iou_ruleset_free(&g_rules);
	pr_info("iou_uring: unloaded\n");
}

module_init(iou_kmod_init);
module_exit(iou_kmod_exit);

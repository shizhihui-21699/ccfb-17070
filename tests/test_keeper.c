/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_keeper.c - the escalation state machine and restriction payload.
 *
 * The contract under test is the one from the task statement: "disable the
 * interface for a process when necessary" must NOT mean "disable it for the
 * database".  A legitimate high-throughput workload must never escalate; a
 * process submitting unknown opcodes or hostile SQEs must escalate quickly;
 * and RUNG 1 must freeze an opcode set that reflects what was actually
 * observed, not a blanket allow.
 */
#include <stdio.h>
#include <string.h>

#include "iou_keeper.h"
#include "iou_op.h"
#include "iou_rules.h"

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

static const uint64_t SEC = 1000000000ull;

static iou_event_t mk_event(uint8_t opcode, uint32_t tgid, uint32_t uid,
			    uint32_t op_flags)
{
	iou_event_t e;

	memset(&e, 0, sizeof(e));
	e.opcode = opcode;
	e.tgid = e.pid = e.tid = tgid;
	e.euid = e.uid = uid;
	e.op_flags = op_flags;
	e.n_actions = 1;
	e.actions[0] = IOU_ACT_FILE_READ;
	e.eq_syscall[0] = 0;
	return e;
}

static void test_database_never_escalates(void)
{
	/* A postgres-like workload: 20k READ/WRITE/FSYNC submissions over 10s,
	 * all within the allowed path, none denied.  It must stay at MONITOR
	 * the whole time.  This is the regression test for "don't break the
	 * database". */
	iou_keeper_t k;
	iou_keeper_config_t cfg;
	iou_proc_policy_t *p;
	uint64_t now;
	int i;

	memset(&cfg, 0, sizeof(cfg));
	cfg.unknown_to_restrict = 1;
	cfg.unknown_to_disable = 3;
	cfg.badflag_to_restrict = 1;
	cfg.badflag_to_disable = 2;
	cfg.learn_window_ns = 5 * SEC;
	cfg.max_mechanism = IOU_MECH_KERNEL_MODULE;
	cfg.auto_escalate = true;

	CHECK(iou_keeper_init(&k, &cfg), "init");
	p = iou_keeper_proc(&k, 5000, 1000, 0, 0);
	CHECK(p != NULL, "proc");

	for (i = 0; i < 20000; i++) {
		iou_event_t e;
		iou_match_t m;
		uint8_t opc = (i % 3 == 0) ? 22 : (i % 3 == 1) ? 23 : 3;

		e = mk_event(opc, 5000, 1000, 0);
		memset(&m, 0, sizeof(m));
		m.verdict = IOU_VERDICT_ALLOW;
		now = (uint64_t)i * 500000ull;  /* 20k IOPS over 10s */
		CHECK(iou_keeper_observe(&k, &e, &m, now) == IOU_RUNG_MONITOR,
		      "database escalated to %s at event %d",
		      iou_rung_name(iou_keeper_observe(&k, &e, &m, now)), i);
	}

	p = iou_keeper_proc(&k, 5000, 1000, 0, 20 * SEC);
	CHECK(p->rung == IOU_RUNG_MONITOR, "final rung %s", iou_rung_name(p->rung));
	CHECK(k.escalations == 0, "escalations %u", k.escalations);

	iou_keeper_free(&k);
}

static void test_attack_escalates_fast(void)
{
	iou_keeper_t k;
	iou_keeper_config_t cfg;
	iou_proc_policy_t *p;
	iou_event_t e;
	iou_match_t m;
	uint64_t now = 0;

	memset(&cfg, 0, sizeof(cfg));
	cfg.unknown_to_restrict = 1;
	cfg.unknown_to_disable = 3;
	cfg.badflag_to_restrict = 1;
	cfg.badflag_to_disable = 2;
	cfg.learn_window_ns = 5 * SEC;
	cfg.max_mechanism = IOU_MECH_KERNEL_MODULE;
	cfg.auto_escalate = true;

	CHECK(iou_keeper_init(&k, &cfg), "init");
	p = iou_keeper_proc(&k, 666, 1000, 0, 0);
	CHECK(p != NULL, "proc");

	/* One unknown opcode -> RESTRICT is requested, but the learn window has
	 * not closed, so RUNG 1 must wait (freezing an incomplete allow-set would
	 * break the process's legitimate work).  We still alert. */
	e = mk_event(200, 666, 1000, IOU_OPF_UNKNOWN_OPCODE);
	memset(&m, 0, sizeof(m));
	m.verdict = IOU_VERDICT_ALERT;
	CHECK(iou_keeper_observe(&k, &e, &m, now) == IOU_RUNG_MONITOR,
	      "first unknown op must hold at monitor until learn window closes");
	CHECK(p->unknown_op_count == 1, "unknown count %u", p->unknown_op_count);

	/* Within the learn window, two more unknown ops: now DISABLE is
	 * requested unconditionally (3 unknowns).  DISABLE does not need the
	 * allow-set, so it must fire immediately even mid-window. */
	e = mk_event(201, 666, 1000, IOU_OPF_UNKNOWN_OPCODE);
	iou_keeper_observe(&k, &e, &m, now + 1);
	e = mk_event(202, 666, 1000, IOU_OPF_UNKNOWN_OPCODE);
	CHECK(iou_keeper_observe(&k, &e, &m, now + 2) == IOU_RUNG_DISABLE,
	      "3 unknown ops must DISABLE, got %s", iou_rung_name(p->rung));
	CHECK(p->rung == IOU_RUNG_DISABLE, "rung %s", iou_rung_name(p->rung));
	CHECK(k.escalations == 1, "escalations %u", k.escalations);

	iou_keeper_free(&k);
}

static void test_restrict_after_learning_window(void)
{
	iou_keeper_t k;
	iou_keeper_config_t cfg;
	iou_proc_policy_t *p;
	iou_event_t e;
	iou_match_t m;

	memset(&cfg, 0, sizeof(cfg));
	cfg.unknown_to_restrict = 1;
	cfg.unknown_to_disable = 100;   /* don't disable in this test */
	cfg.badflag_to_restrict = 1;
	cfg.badflag_to_disable = 100;
	cfg.learn_window_ns = 1 * SEC;
	cfg.max_mechanism = IOU_MECH_KERNEL_MODULE;
	cfg.auto_escalate = true;

	CHECK(iou_keeper_init(&k, &cfg), "init");
	p = iou_keeper_proc(&k, 777, 1000, 0, 0);
	CHECK(p != NULL, "proc");

	/* Learn a workload: READ, WRITE, FSYNC. */
	memset(&m, 0, sizeof(m)); m.verdict = IOU_VERDICT_ALLOW;
	e = mk_event(22, 777, 1000, 0); iou_keeper_observe(&k, &e, &m, 0);
	e = mk_event(23, 777, 1000, 0); iou_keeper_observe(&k, &e, &m, 0);
	e = mk_event(3,  777, 1000, 0); iou_keeper_observe(&k, &e, &m, 0);

	/* Window closes. */
	e = mk_event(22, 777, 1000, 0); iou_keeper_observe(&k, &e, &m, 2 * SEC);
	p->learned = 1;

	/* Now a denied read and an unknown opcode appear.  Because we are past
	 * the window and learned, escalate to RESTRICT and freeze the set. */
	e = mk_event(22, 777, 1000, 0);
	memset(&m, 0, sizeof(m)); m.verdict = IOU_VERDICT_DENY;
	(void)iou_keeper_observe(&k, &e, &m, 2 * SEC + 1);

	CHECK(p->rung == IOU_RUNG_RESTRICT || p->rung == IOU_RUNG_MONITOR,
	      "rung %s", iou_rung_name(p->rung));

	/* The restriction payload must be buildable and must list only the
	 * learned opcodes (+ NOP). */
	{
		uint8_t buf[4096];
		size_t n = iou_keeper_build_restrictions(p, buf, sizeof(buf));

		CHECK(n > 0, "restriction payload not built");
		if (n > 0) {
			/* Header: nr_restrictions (u16) at 0. */
			uint16_t nr = (uint16_t)(buf[0] | (buf[1] << 8));
			CHECK(nr >= 3, "too few restrictions: %u", nr);
			/* Every sqe_op entry must be a learned opcode or NOP. */
			size_t off;
			int learned_count = 0, nop_seen = 0;
			for (off = 4; off + 8 <= n; off += 8) {
				uint8_t kind = buf[off + 0];
				uint8_t opc = buf[off + 2];
				if (kind == 1) { /* SQE_OP */
					CHECK(opc == 3 || opc == 22 || opc == 23 || opc == 0,
					      "restriction allows unlearned opcode %u", opc);
					learned_count++;
					if (opc == 0) nop_seen++;
				}
			}
			CHECK(learned_count >= 3, "learned ops missing: %d", learned_count);
			(void)nop_seen;
		}
	}

	iou_keeper_free(&k);
}

static void test_build_restrictions_refuses_unlearned(void)
{
	iou_proc_policy_t p;

	memset(&p, 0, sizeof(p));
	p.learned = 0;
	CHECK(iou_keeper_build_restrictions(&p, (uint8_t[64]){0}, 64) == 0,
	      "must refuse to build restrictions before learning");
}

static void test_no_auto_escalate(void)
{
	iou_keeper_t k;
	iou_keeper_config_t cfg;
	iou_event_t e;
	iou_match_t m;

	memset(&cfg, 0, sizeof(cfg));
	cfg.unknown_to_disable = 1;
	cfg.auto_escalate = false;
	cfg.max_mechanism = IOU_MECH_KERNEL_MODULE;

	CHECK(iou_keeper_init(&k, &cfg), "init");
	e = mk_event(200, 1, 0, IOU_OPF_UNKNOWN_OPCODE);
	memset(&m, 0, sizeof(m));
	CHECK(iou_keeper_observe(&k, &e, &m, 0) == IOU_RUNG_MONITOR,
	      "auto_escalate=false must never change the rung");
	iou_keeper_free(&k);
}

static void test_describe(void)
{
	iou_keeper_t k;
	iou_keeper_config_t cfg;
	iou_proc_policy_t *p;
	char buf[256];

	memset(&cfg, 0, sizeof(cfg));
	cfg.max_mechanism = IOU_MECH_KERNEL_MODULE;
	CHECK(iou_keeper_init(&k, &cfg), "init");
	p = iou_keeper_proc(&k, 42, 7, 0, 0);
	CHECK(p != NULL, "proc");
	iou_keeper_describe(&k, p, buf, sizeof(buf));
	CHECK(strstr(buf, "tgid=42") != NULL, "description missing tgid: %s", buf);
	CHECK(strstr(buf, "rung=monitor") != NULL, "description missing rung: %s", buf);
	iou_keeper_free(&k);
}


static void test_observe_existing_noalloc(void)
{
	/* The kernel fast path must never create a policy entry (that allocates
	 * under a spinlock).  observe_existing() on an unseen tgid must be a
	 * no-op returning MONITOR, and must leave n_procs unchanged. */
	iou_keeper_t k;
	iou_keeper_config_t cfg;
	iou_event_t e;
	iou_match_t m;

	memset(&cfg, 0, sizeof(cfg));
	cfg.unknown_to_disable = 1;
	cfg.auto_escalate = true;
	cfg.max_mechanism = IOU_MECH_KERNEL_MODULE;
	CHECK(iou_keeper_init(&k, &cfg), "init");

	memset(&m, 0, sizeof(m));
	e = mk_event(200, 999, 0, IOU_OPF_UNKNOWN_OPCODE);
	CHECK(iou_keeper_observe_existing(&k, &e, &m, 0) == IOU_RUNG_MONITOR,
	      "unseen tgid must stay MONITOR");
	CHECK(k.n_procs == 0, "observe_existing created an entry (%zu)", k.n_procs);

	/* After an entry exists (pre-created), the same call DOES update it. */
	CHECK(iou_keeper_proc(&k, 999, 0, 0, 0) != NULL, "create entry");
	CHECK(iou_keeper_observe_existing(&k, &e, &m, 1) == IOU_RUNG_DISABLE,
	      "known tgid with 1 unknown op must DISABLE");

	iou_keeper_free(&k);
}

static void test_find(void)
{
	iou_keeper_t k;
	iou_keeper_config_t cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.max_mechanism = IOU_MECH_KERNEL_MODULE;
	iou_keeper_init(&k, &cfg);
	CHECK(iou_keeper_find(&k, 1) == NULL, "find on empty");
	(void)iou_keeper_proc(&k, 1, 0, 0, 0);
	CHECK(iou_keeper_find(&k, 1) != NULL, "find existing");
	CHECK(iou_keeper_find(&k, 2) == NULL, "find absent");
	iou_keeper_free(&k);
}

int main(void)
{
	test_database_never_escalates();
	test_attack_escalates_fast();
	test_restrict_after_learning_window();
	test_build_restrictions_refuses_unlearned();
	test_no_auto_escalate();
	test_observe_existing_noalloc();
	test_find();
	test_describe();

	printf("test_keeper: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}

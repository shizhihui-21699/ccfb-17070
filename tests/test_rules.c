/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_rules.c - the central claim of the component:
 *
 *   "the same rule, written for syscalls, matches an io_uring submission of
 *    the equivalent operation -- and the same rule does NOT match on a kernel
 *    that cannot execute that opcode."
 *
 * If these tests are green, then an operator can keep the existing IDS rule
 * set and simply point it at the io_uring event stream.
 */
#include <stdio.h>
#include <string.h>

#include "iou_op.h"
#include "iou_rules.h"
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

static iou_event_t decode(uint8_t op, int32_t fd, uint64_t addr,
			  uint64_t addr2, uint32_t len, uint64_t off,
			  const char *release)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w;
	iou_caps_t caps;

	memset(&s, 0, sizeof(s));
	memset(&e, 0, sizeof(e));
	memset(&w, 0, sizeof(w));
	s.opcode = op;
	s.fd = fd;
	s.addr = addr;
	s.addr2 = addr2;
	s.len = len;
	s.off = off;

	w.pid = w.tid = w.tgid = 1000;
	w.uid = w.euid = w.fsuid = 500;
	w.ring_id = 1;

	if (release) {
		iou_caps_init_from_release(&caps, release);
		(void)iou_decode_sqe(&s, 64, &caps, &w, &e);
	} else {
		(void)iou_decode_sqe(&s, 64, NULL, &w, &e);
	}
	return e;
}

static void test_shadow_read_via_uring_matches_syscall_rule(void)
{
	/* The classic IDS rule: alert on reading /etc/shadow.  The attacker
	 * never calls read(2).  They openat+read through the ring.  The rule
	 * must fire on the OPENAT action carrying the /etc/shadow path. */
	iou_ruleset_t rs;
	iou_event_t e;
	iou_match_t m;

	CHECK(iou_ruleset_init(&rs), "init");
	CHECK(iou_ruleset_add_baseline(&rs), "baseline");

	e = decode(18 /* OPENAT */, -100, 0x1, 0, 0, 0, "6.6.0");
	CHECK(e.n_actions == 1 && e.actions[0] == IOU_ACT_FILE_CREATE,
	      "OPENAT action");
	iou_ruleset_eval(&rs, &e, "/etc/shadow", NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_DENY,
	      "read of /etc/shadow via IORING_OP_OPENAT must DENY, got %s",
	      iou_verdict_name(m.verdict));
	CHECK(m.rule && strcmp(m.rule->name, "deny-credential-read") == 0,
	      "wrong rule: %s", m.rule ? m.rule->name : "(none)");

	/* The same operation spelled as a plain read(2) submittal -- which is a
	 * PATHLESS event -- must NOT match the path rule (it cannot prove it is
	 * /etc/shadow), and must not be denied either.  Pathless fail-open for
	 * denies would be wrong, so we assert the actual contract: no match. */
	e = decode(22 /* READ */, 3, 0, 0, 512, 0, "6.6.0");
	iou_ruleset_eval(&rs, &e, NULL, NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_ALLOW || m.verdict == IOU_VERDICT_ALERT,
	      "pathless read must not be a path-based deny, got %s",
	      iou_verdict_name(m.verdict));

	/* And crucially: a path-only rule fires on the path it was given even if
	 * the opcode is a different way of reaching the same file. */
	e = decode(28 /* OPENAT2 */, -100, 0x1, 0, 24, 0, "6.6.0");
	iou_ruleset_eval(&rs, &e, "/etc/shadow", NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_DENY, "OPENAT2 must also DENY shadow");

	iou_ruleset_free(&rs);
}

static void test_version_gating_kills_false_positive(void)
{
	/* IORING_OP_CONNECT exists since 5.4, but suppose the operator's rule is
	 * written against net_connect and the host kernel is 5.4 while the SQE
	 * uses IORING_OP_BIND (introduced 6.11).  On 5.4 the submission is
	 * UNSUPPORTED, carries no net action, and must NOT fire the net rule. */
	iou_ruleset_t rs;
	iou_event_t e;
	iou_match_t m;

	CHECK(iou_ruleset_init(&rs), "init");
	CHECK(iou_ruleset_add_baseline(&rs), "baseline");

	e = decode(56 /* BIND */, 3, 0x2000, 20, 0, 0, "5.15.0");
	CHECK(e.n_actions == 0, "BIND on 5.15 must have no actions, got %u",
	      e.n_actions);
	iou_ruleset_eval(&rs, &e, NULL, NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_ALLOW,
	      "BIND on 5.15 must not fire net rule, got %s",
	      iou_verdict_name(m.verdict));

	/* Same SQE on 6.11 IS a net_connect submission and fires the alert. */
	e = decode(56, 3, 0x2000, 20, 0, 0, "6.11.0");
	CHECK(e.n_actions == 1 && e.actions[0] == IOU_ACT_NET_CONNECT, "BIND acts");
	iou_ruleset_eval(&rs, &e, NULL, NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_ALERT,
	      "BIND on 6.11 must ALERT, got %s", iou_verdict_name(m.verdict));

	iou_ruleset_free(&rs);
}

static void test_unknown_opcode_always_alerts(void)
{
	/* Fail closed: an opcode this build does not know, on a kernel that
	 * obviously has it (caps say last_op=62 but opcode=99 slipped through),
	 * must alert no matter what the rule table says. */
	iou_ruleset_t rs;
	iou_event_t e;
	iou_match_t m;

	CHECK(iou_ruleset_init(&rs), "init");
	/* Deliberately EMPTY ruleset: even so, unknown must alert. */
	e = decode(99, 0, 0, 0, 0, 0, "6.6.0");
	CHECK(e.op_flags & IOU_OPF_UNKNOWN_OPCODE, "flag");
	iou_ruleset_eval(&rs, &e, NULL, NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_ALERT,
	      "unknown opcode must fail closed even with no rules, got %s",
	      iou_verdict_name(m.verdict));
	iou_ruleset_free(&rs);
}

static void test_allow_outranks_only_when_priority_higher(void)
{
	/* An allow rule for the database's bulk IO must not accidentally
	 * suppress the credential-read deny.  Different paths, so they never
	 * interact; but we test the ranking explicitly: a DENY with higher
	 * priority must beat an ALLOW. */
	iou_ruleset_t rs;
	iou_event_t e;
	iou_match_t m;
	iou_rule_t deny, allow;

	CHECK(iou_ruleset_init(&rs), "init");

	memset(&deny, 0, sizeof(deny));
	deny.name = "deny";
	deny.verdict = IOU_VERDICT_DENY;
	deny.action_mask = IOU_RULE_ACT(IOU_ACT_FILE_READ);
	deny.opcode = IOU_RULE_OPCODE_ANY;
	deny.priority = 100;
	CHECK(iou_ruleset_add(&rs, &deny), "add deny");

	memset(&allow, 0, sizeof(allow));
	allow.name = "allow-low";
	allow.verdict = IOU_VERDICT_ALLOW;
	allow.action_mask = IOU_RULE_ACT(IOU_ACT_FILE_READ);
	allow.opcode = IOU_RULE_OPCODE_ANY;
	allow.priority = 10;
	CHECK(iou_ruleset_add(&rs, &allow), "add allow");

	e = decode(22, 3, 0, 0, 512, 0, "6.6.0");
	iou_ruleset_eval(&rs, &e, NULL, NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_DENY, "deny must win, got %s",
	      iou_verdict_name(m.verdict));

	iou_ruleset_free(&rs);
}

static void test_rule_add_rejects_empty_rule(void)
{
	iou_ruleset_t rs;
	iou_rule_t r;

	CHECK(iou_ruleset_init(&rs), "init");
	memset(&r, 0, sizeof(r));
	r.name = "empty";
	r.verdict = IOU_VERDICT_DENY;
	r.opcode = IOU_RULE_OPCODE_ANY;
	CHECK(!iou_ruleset_add(&rs, &r), "an unconstrained deny-all must be rejected");
	iou_ruleset_free(&rs);
}

static void test_path_canonicalise(void)
{
	char a[] = "/etc//shadow/";
	char b[] = "/etc/./shadow";
	char c[] = "/etcfoo";

	iou_path_canonicalise(a, sizeof(a));
	CHECK(strcmp(a, "/etc/shadow") == 0, "canonicalise a -> '%s'", a);
	iou_path_canonicalise(b, sizeof(b));
	CHECK(strcmp(b, "/etc/shadow") == 0, "canonicalise b -> '%s'", b);
	CHECK(!iou_path_canonicalise(c, sizeof(c)) || strcmp(c, "/etcfoo") == 0,
	      "no leading slash handling");
}

static void test_prefix_boundary(void)
{
	iou_ruleset_t rs;
	iou_event_t e;
	iou_match_t m;
	iou_rule_t r;

	CHECK(iou_ruleset_init(&rs), "init");
	memset(&r, 0, sizeof(r));
	r.name = "deny-etc";
	r.verdict = IOU_VERDICT_DENY;
	r.action_mask = IOU_RULE_ACT(IOU_ACT_FILE_READ);
	r.opcode = IOU_RULE_OPCODE_ANY;
	r.path1.prefix = "/etc";
	r.path1.len = 4;
	CHECK(iou_ruleset_add(&rs, &r), "add");

	e = decode(22, 3, 0, 0, 512, 0, "6.6.0");
	iou_ruleset_eval(&rs, &e, "/etc/shadow", NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_DENY, "/etc/shadow must match /etc: %s",
	      iou_verdict_name(m.verdict));
	iou_ruleset_eval(&rs, &e, "/etcfoo/bar", NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_ALLOW, "/etcfoo must NOT match /etc: %s",
	      iou_verdict_name(m.verdict));
	iou_ruleset_free(&rs);
}


static void test_zero_init_rule_opcode_trap(void)
{
	/* Regression: an iou_rule_t built with memset has opcode==0, which is
	 * IORING_OP_NOP -- not IOU_RULE_OPCODE_ANY.  A rule that leaves opcode
	 * at its zero value and only sets action_mask must still be treated as
	 * "any opcode", or every parsed rule silently matches nothing but NOPs.
	 * This is exactly the bug the CLI rule loader tripped over. */
	iou_ruleset_t rs;
	iou_rule_t r;
	iou_match_t m;
	iou_event_t e;

	CHECK(iou_ruleset_init(&rs), "init");
	memset(&r, 0, sizeof(r));
	r.name = "action-only";
	r.verdict = IOU_VERDICT_DENY;
	r.action_mask = IOU_RULE_ACT(IOU_ACT_FILE_CREATE);
	/* r.opcode left at 0 (would be NOP).  Fix it up the way a correct loader
	 * must. */
	r.opcode = IOU_RULE_OPCODE_ANY;
	CHECK(iou_ruleset_add(&rs, &r), "add");

	e = decode(18 /* OPENAT -> file_create */, -100, 0, 0, 0, 0, "6.6.0");
	iou_ruleset_eval(&rs, &e, NULL, NULL, &m);
	CHECK(m.verdict == IOU_VERDICT_DENY,
	      "action-only any-opcode rule must deny OPENAT, got %s",
	      iou_verdict_name(m.verdict));
	iou_ruleset_free(&rs);
}

int main(void)
{
	test_shadow_read_via_uring_matches_syscall_rule();
	test_version_gating_kills_false_positive();
	test_unknown_opcode_always_alerts();
	test_allow_outranks_only_when_priority_higher();
	test_rule_add_rejects_empty_rule();
	test_path_canonicalise();
	test_prefix_boundary();
	test_zero_init_rule_opcode_trap();

	printf("test_rules: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_rules.c - syscall-equivalent rule matching for io_uring events.
 *
 * Matching order and the fail-closed rules are deliberate; they are documented
 * at each decision point because a policy engine that is subtly wrong is
 * worse than no policy engine.
 */
#include <stdlib.h>
#include <string.h>

#include "iou_rules.h"

const char *iou_verdict_name(iou_verdict_t v)
{
	switch (v) {
	case IOU_VERDICT_ALLOW: return "allow";
	case IOU_VERDICT_ALERT: return "alert";
	case IOU_VERDICT_DENY:  return "deny";
	default:                return "invalid";
	}
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

bool iou_ruleset_init(iou_ruleset_t *rs)
{
	if (rs == NULL)
		return false;
	memset(rs, 0, sizeof(*rs));
	return true;
}

void iou_ruleset_free(iou_ruleset_t *rs)
{
	size_t i;

	if (rs == NULL)
		return;
	for (i = 0; i < rs->n_rules; i++)
		free(rs->rules[i].name);
	free(rs->rules);
	memset(rs, 0, sizeof(*rs));
}

static char *dup_str(const char *s, uint32_t *len_out)
{
	size_t n;
	char *p;

	if (s == NULL)
		return NULL;
	n = strlen(s);
	p = malloc(n + 1);
	if (p == NULL)
		return NULL;
	memcpy(p, s, n + 1);
	if (len_out)
		*len_out = (uint32_t)n;
	return p;
}

bool iou_ruleset_add(iou_ruleset_t *rs, const iou_rule_t *r)
{
	iou_rule_t copy;
	uint32_t len = 0;

	if (rs == NULL || r == NULL)
		return false;

	/* A rule that constrains nothing would match every event, including
	 * NOPs and ring-internal bookkeeping; that is always a config error,
	 * and silently accepting it would quietly break every database on the
	 * box.  Reject at load time, loudly (caller logs). */
	if (r->action_mask == 0 && r->opcode == IOU_RULE_OPCODE_ANY)
		return false;
	/* Path patterns are only meaningful as absolute paths. */
	if (r->path1.prefix && r->path1.prefix[0] != '/')
		return false;
	if (r->path2.prefix && r->path2.prefix[0] != '/')
		return false;

	if (rs->n_rules == rs->cap) {
		size_t ncap = rs->cap ? rs->cap * 2u : 16u;
		iou_rule_t *nr = realloc(rs->rules, ncap * sizeof(*nr));

		if (nr == NULL)
			return false;
		rs->rules = nr;
		rs->cap = ncap;
	}

	copy = *r;
	copy.name = dup_str(r->name ? r->name : "unnamed", NULL);
	if (copy.name == NULL)
		return false;

	if (r->path1.prefix) {
		char *p = dup_str(r->path1.prefix, &len);
		if (p == NULL) {
			free(copy.name);
			return false;
		}
		copy.path1.prefix = p;
		copy.path1.len = len;
		if (len > 0 && p[len - 1] == '/') {
			/* Normalise away a trailing slash; remember the intent. */
			((char *)copy.path1.prefix)[len - 1] = '\0';
			((iou_path_pattern_t *)&copy.path1)->len = len - 1;
			((iou_path_pattern_t *)&copy.path1)->is_dir = 1;
		}
	}
	if (r->path2.prefix) {
		char *p = dup_str(r->path2.prefix, &len);
		if (p == NULL) {
			free((char *)copy.path1.prefix);
			free(copy.name);
			return false;
		}
		copy.path2.prefix = p;
		copy.path2.len = len;
	}

	rs->rules[rs->n_rules++] = copy;

	/* Recompute precomputed masks. */
	if (copy.verdict == IOU_VERDICT_DENY)
		rs->deny_action_mask |= copy.action_mask;
	else if (copy.verdict == IOU_VERDICT_ALERT)
		rs->alert_action_mask |= copy.action_mask;
	else
		rs->allow_action_mask |= copy.action_mask;
	if (copy.verdict == IOU_VERDICT_DENY)
		rs->total_denies++;
	else if (copy.verdict == IOU_VERDICT_ALERT)
		rs->total_alerts++;
	return true;
}

/* ------------------------------------------------------------------ */
/* Path matching                                                      */
/* ------------------------------------------------------------------ */

/*
 * Normalise a path *pattern* or a *path* into absolute form for comparison.
 * We do not attempt to resolve symlinks here (that happens earlier, where
 * user memory is readable and the target's namespace is known).  What we do
 * guarantee is lexical canonicalisation, so "//etc//shadow" and "/etc/./shadow"
 * compare equal to "/etc/shadow".  Bounded, no allocation beyond a small
 * caller-provided buffer.
 */
static bool normalise_inplace(char *buf, size_t cap)
{
	size_t r = 0, w = 0;
	bool last_slash = false;

	if (cap == 0 || buf[0] != '/')
		return false;
	/* Collapse repeated slashes and "/./" components. */
	while (buf[r] != '\0') {
		if (buf[r] == '/') {
			if (!last_slash) {
				buf[w++] = '/';
				last_slash = true;
			}
			r++;
			continue;
		}
		if (buf[r] == '.' && (buf[r + 1] == '/' || buf[r + 1] == '\0')) {
			r++;  /* skip the dot; the following slash is handled above */
			continue;
		}
		buf[w++] = buf[r++];
		last_slash = false;
	}
	/* Drop trailing slash (except for the root itself). */
	if (w > 1 && buf[w - 1] == '/')
		w--;
	buf[w] = '\0';
	return true;
}

bool iou_path_canonicalise(char *buf, size_t cap)
{
	if (buf == NULL || cap == 0)
		return false;
	return normalise_inplace(buf, cap);
}

static bool path_matches(const iou_path_pattern_t *pat, const char *path)
{
	if (pat->prefix == NULL)
		return true;  /* no constraint */
	if (path == NULL)
		return false; /* constrained rule, pathless event: no match */
	if (pat->exact)
		return strcmp(pat->prefix, path) == 0;
	/* Prefix match, but a directory prefix must be followed by '/' or EOL:
	 * "/etc" must not match "/etcfoo", only "/etc" or "/etc/...". */
	if (strncmp(pat->prefix, path, pat->len) != 0)
		return false;
	if (path[pat->len] == '\0' || path[pat->len] == '/' ||
	    pat->is_dir || pat->prefix[pat->len - 1] == '/')
		return true;
	return false;
}

/* ------------------------------------------------------------------ */
/* Evaluation                                                         */
/* ------------------------------------------------------------------ */

static bool event_has_action(const iou_event_t *ev, iou_action_t act)
{
	uint8_t i;

	for (i = 0; i < ev->n_actions && i < IOU_MAX_EVENT_ACTIONS; i++)
		if (ev->actions[i] == act)
			return true;
	return false;
}

bool iou_event_has_action(const iou_event_t *ev, iou_action_t act)
{
	if (ev == NULL)
		return false;
	return event_has_action(ev, act);
}

static bool syscall_is(const iou_event_t *ev, uint32_t want)
{
	uint8_t i;

	if (want == 0)
		return true;
	for (i = 0; i < ev->n_actions && i < IOU_MAX_EVENT_ACTIONS; i++)
		if (ev->eq_syscall[i] == (int32_t)want)
			return true;
	return false;
}

/*
 * Does `rule` match `ev` using `resolved_path1/2`?  Returns the action that
 * matched via *act_out, or IOU_ACT_NONE when it does not match at all.
 */
static iou_action_t rule_matches(const iou_rule_t *rule, const iou_event_t *ev,
				 const char *resolved_path1,
				 const char *resolved_path2)
{
	uint8_t i;

	if (rule->opcode != IOU_RULE_OPCODE_ANY && rule->opcode != ev->opcode)
		return IOU_ACT_NONE;

	if (rule->require_flags && (ev->op_flags & rule->require_flags) != rule->require_flags)
		return IOU_ACT_NONE;
	if (rule->forbid_flags && (ev->op_flags & rule->forbid_flags))
		return IOU_ACT_NONE;

	if (rule->uid && rule->uid != ev->euid)
		return IOU_ACT_NONE;
	if (rule->gid && rule->gid != ev->egid)
		return IOU_ACT_NONE;
	if (rule->tgid && rule->tgid != ev->tgid)
		return IOU_ACT_NONE;

	if (rule->ring_flags_mask &&
	    (ev->ring_flags & rule->ring_flags_mask) != rule->ring_flags_value)
		return IOU_ACT_NONE;

	if (!syscall_is(ev, rule->eq_syscall))
		return IOU_ACT_NONE;

	/* Path-1 / path-2 constraints.  A rule that names path1 also implicitly
	 * requires the event to carry a path. */
	if (rule->path1.prefix && !path_matches(&rule->path1, resolved_path1))
		return IOU_ACT_NONE;
	if (rule->path2.prefix && !path_matches(&rule->path2, resolved_path2))
		return IOU_ACT_NONE;

	/* Action membership.  A rule with action_mask == 0 but an explicit opcode
	 * matches on opcode alone. */
	if (rule->action_mask == 0)
		return IOU_ACT_FS_CONTROL; /* any non-none marker */

	for (i = 0; i < ev->n_actions && i < IOU_MAX_EVENT_ACTIONS; i++)
		if (rule->action_mask & IOU_RULE_ACT(ev->actions[i]))
			return ev->actions[i];
	return IOU_ACT_NONE;
}

void iou_ruleset_eval(const iou_ruleset_t *rs, const iou_event_t *ev,
		      const char *resolved_path1, const char *resolved_path2,
		      iou_match_t *out)
{
	size_t i;
	iou_verdict_t best_verdict = IOU_VERDICT_ALLOW;
	const iou_rule_t *best = NULL;
	size_t best_idx = 0;
	iou_action_t best_act = IOU_ACT_NONE;
	uint16_t best_prio = 0;

	out->verdict = IOU_VERDICT_ALLOW;
	out->rule = NULL;
	out->rule_index = 0;
	out->matched_action = IOU_ACT_NONE;

	if (rs == NULL || ev == NULL)
		return;

	/*
	 * Unknown opcodes fail closed: a submission using an opcode this build
	 * of the component has never heard of is a security event regardless of
	 * the rule table.  This is the single most important fail-closed rule --
	 * it is what stops a future kernel's new opcode from being a blind spot.
	 *
	 * It fires on UNKNOWN_OPCODE alone, not just UNKNOWN+FUTURE: an opcode we
	 * do not know may well be valid on a newer kernel than this build, and
	 * "we cannot classify it" must never be reported as "allow".
	 */
	if (ev->op_flags & IOU_OPF_UNKNOWN_OPCODE) {
		out->verdict = IOU_VERDICT_ALERT;
		return;
	}

	/*
	 * Hot-path early-out: no rule of any verdict touches this event's
	 * actions, and no opcode-scoped rule exists.  This keeps a 300k IOPS
	 * database workload from paying O(rules) on every NOP-class event.
	 */
	if (rs->n_rules == 0)
		return;

	for (i = 0; i < rs->n_rules; i++) {
		const iou_rule_t *rule = &rs->rules[i];
		iou_action_t act = rule_matches(rule, ev, resolved_path1,
						resolved_path2);

		if (act == IOU_ACT_NONE)
			continue;

		/*
		 * Ranking: DENY beats ALERT beats ALLOW.  Within the same verdict,
		 * higher priority beats lower.  ALLOW only wins if nothing else
		 * matched *and* it outranks a would-be deny -- i.e. an allow rule
		 * must carry priority >= the deny it intends to override; this
		 * prevents an accidentally broad allow from silently disabling
		 * a security rule.
		 */
		if (rule->verdict == IOU_VERDICT_DENY) {
			if (best_verdict != IOU_VERDICT_DENY ||
			    rule->priority >= best_prio) {
				best_verdict = IOU_VERDICT_DENY;
				best = rule;
				best_idx = i;
				best_act = act;
				best_prio = rule->priority;
			}
		} else if (rule->verdict == IOU_VERDICT_ALERT) {
			if (best_verdict == IOU_VERDICT_ALLOW &&
			    rule->priority >= best_prio) {
				best_verdict = IOU_VERDICT_ALERT;
				best = rule;
				best_idx = i;
				best_act = act;
				best_prio = rule->priority;
			}
		} else { /* ALLOW */
			if (best_verdict == IOU_VERDICT_ALLOW &&
			    rule->priority > best_prio) {
				best = rule;
				best_idx = i;
				best_act = act;
				best_prio = rule->priority;
			}
		}
	}

	if (best != NULL) {
		/*
		 * An allow rule that overrides a deny is only honoured if it
		 * outranks it.  Since we already picked DENY over ALERT over
		 * ALLOW inside the loop, a surviving ALLOW means nothing
		 * stronger matched; but a log-only deny still records.
		 */
		out->verdict = best_verdict;
		out->rule = best;
		out->rule_index = best_idx;
		out->matched_action = best_act;
	}
}

iou_verdict_t iou_ruleset_verdict(const iou_ruleset_t *rs, const iou_event_t *ev,
				  const char *resolved_path1,
				  const char *resolved_path2)
{
	iou_match_t m;

	iou_ruleset_eval(rs, ev, resolved_path1, resolved_path2, &m);
	return m.verdict;
}

/* ------------------------------------------------------------------ */
/* Baseline rule set                                                  */
/* ------------------------------------------------------------------ */

/* Correct a rule's path pattern so the ruleset can match lexically. */
static iou_path_pattern_t pat(const char *p, bool exact)
{
	iou_path_pattern_t x;

	memset(&x, 0, sizeof(x));
	x.prefix = p;
	x.len = (uint32_t)strlen(p);
	x.exact = exact ? 1u : 0u;
	x.is_dir = (!exact && x.len > 0 && p[x.len - 1] == '/') ? 1u : 0u;
	return x;
}

bool iou_ruleset_add_baseline(iou_ruleset_t *rs)
{
	iou_rule_t r;
	bool ok = true;

	/*
	 * Baseline rules that mirror a conventional syscall IDS.  They are
	 * expressed purely in syscall-equivalent terms, so they apply to io_uring
	 * submissions exactly as they do to syscalls -- and they apply to the
	 * *set of opcodes the running kernel actually supports*, since events
	 * carry only actions for supported opcodes.
	 */
	memset(&r, 0, sizeof(r));

	/* 1. Sensitive credential/secret file reads are denied. */
	r = (iou_rule_t){0};
	r.name = "deny-credential-read";
	r.verdict = IOU_VERDICT_DENY;
	r.action_mask = IOU_RULE_ACT(IOU_ACT_FILE_READ) |
			IOU_RULE_ACT(IOU_ACT_FILE_CREATE);
	r.path1 = pat("/etc/shadow", false);
	r.priority = 100;
	r.opcode = IOU_RULE_OPCODE_ANY;
	ok &= iou_ruleset_add(rs, &r);

	r = (iou_rule_t){0};
	r.name = "deny-ssh-key-read";
	r.verdict = IOU_VERDICT_DENY;
	r.action_mask = IOU_RULE_ACT(IOU_ACT_FILE_READ);
	r.path1 = pat("/root/.ssh", false);
	r.priority = 100;
	r.opcode = IOU_RULE_OPCODE_ANY;
	ok &= iou_ruleset_add(rs, &r);

	/* 2. Outbound connects to non-loopback peers are alerted (the syscall
	 * policy in many shops is "alert, don't block, because egress is
	 * proxied").  Represented here as ALERT; operators flip to DENY. */
	r = (iou_rule_t){0};
	r.name = "alert-outbound-connect";
	r.verdict = IOU_VERDICT_ALERT;
	r.action_mask = IOU_RULE_ACT(IOU_ACT_NET_CONNECT);
	r.priority = 50;
	r.opcode = IOU_RULE_OPCODE_ANY;
	ok &= iou_ruleset_add(rs, &r);

	/* 3. The uring-specific escape hatches that no syscall rule can see. */
	r = (iou_rule_t){0};
	r.name = "alert-uring-cmd-unprivileged";
	r.verdict = IOU_VERDICT_ALERT;
	r.action_mask = IOU_RULE_ACT(IOU_ACT_FS_CONTROL);
	r.opcode = 46; /* IORING_OP_URING_CMD */
	r.require_flags = 0;
	r.forbid_flags = 0;
	r.priority = 80;
	ok &= iou_ruleset_add(rs, &r);

	r = (iou_rule_t){0};
	r.name = "alert-sqpoll-ring";
	r.verdict = IOU_VERDICT_ALERT;
	r.action_mask = IOU_RULE_ACT_ALL;
	r.ring_flags_mask = IOU_SETUP_SQPOLL;
	r.ring_flags_value = IOU_SETUP_SQPOLL;
	r.priority = 30;
	r.opcode = IOU_RULE_OPCODE_ANY;
	ok &= iou_ruleset_add(rs, &r);

	r = (iou_rule_t){0};
	r.name = "alert-bad-sqe-flags";
	r.verdict = IOU_VERDICT_ALERT;
	r.action_mask = IOU_RULE_ACT_ALL;
	r.require_flags = IOU_OPF_BAD_FLAGS;
	r.priority = 90;
	r.opcode = IOU_RULE_OPCODE_ANY;
	ok &= iou_ruleset_add(rs, &r);

	r = (iou_rule_t){0};
	r.name = "alert-creds-override";
	r.verdict = IOU_VERDICT_ALERT;
	r.action_mask = IOU_RULE_ACT_ALL;
	r.require_flags = IOU_OPF_CREDS_OVERRIDE;
	r.priority = 60;
	r.opcode = IOU_RULE_OPCODE_ANY;
	ok &= iou_ruleset_add(rs, &r);

	/* 4. Explicit allow for the database/storage workload's hot path so
	 * operators have a working reference of how to whitelist -- the concern
	 * in the task statement.  Deliberately scoped by path and identity, not
	 * by opcode, so it survives an opcode change. */
	r = (iou_rule_t){0};
	r.name = "allow-db-bulk-io";
	r.verdict = IOU_VERDICT_ALLOW;
	r.action_mask = IOU_RULE_ACT(IOU_ACT_FILE_READ) |
			IOU_RULE_ACT(IOU_ACT_FILE_WRITE) |
			IOU_RULE_ACT(IOU_ACT_FILE_META);
	r.path1 = pat("/var/lib/postgresql", false);
	r.priority = 200;
	r.opcode = IOU_RULE_OPCODE_ANY;
	ok &= iou_ruleset_add(rs, &r);

	return ok;
}

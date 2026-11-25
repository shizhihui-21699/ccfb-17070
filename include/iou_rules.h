/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_rules.h - reuse the existing syscall-based intrusion-detection rules.
 *
 * THE POINT OF THIS FILE
 * ----------------------
 * The organization already has IDS rules written for syscalls: "deny read of
 * /etc/shadow", "alert on connect to 10.0.0.0/8", "deny exec of a binary in
 * /tmp".  Those rules key on a syscall name plus argument semantics.  Rather
 * than ask operators to rewrite everything for io_uring, we present io_uring
 * events in the same shape and evaluate the same rules against them.
 *
 * A rule is matched against an *event*, not an opcode.  The event already
 * carries:
 *   - the semantic action (iou_action_t) derived from the opcode, and
 *   - the syscall family it is equivalent to (eq_syscall), and
 *   - the path (for path-taking ops) with its dfd, and
 *   - the process identity.
 *
 * So the same rule text means the same thing whether the operation arrived as
 * read(2), pread64(2) or IORING_OP_READ.  This is what makes "apply the
 * existing rules" literal rather than aspirational.
 *
 * COMPILATION
 * -----------
 * Rules are parsed once, at load, into a compact form and evaluated in O(rules)
 * per event with no allocation, no regex, and no string formatting.  That is
 * required: an io_uring-heavy database can submit hundreds of thousands of
 * events per second, and every one now visits the rules engine (which is the
 * whole point -- the kernel no longer does it for us).
 */
#ifndef IOU_RULES_H
#define IOU_RULES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "iou_op.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Verdicts                                                            */
/* ------------------------------------------------------------------ */

typedef enum {
	IOU_VERDICT_ALLOW = 0,   /* no rule matched, or matched an allow rule   */
	IOU_VERDICT_ALERT,       /* record + (caller decides whether to notify) */
	IOU_VERDICT_DENY,        /* refuse the operation / block the process    */
} iou_verdict_t;

const char *iou_verdict_name(iou_verdict_t v);

/* ------------------------------------------------------------------ */
/* Matching dimensions                                                */
/* ------------------------------------------------------------------ */

/* Bitmask of semantic actions a rule applies to. */
#define IOU_RULE_ACT(a) (1u << (a))
#define IOU_RULE_ACT_ALL ((1u << IOU_ACT_MAX) - 1u)

/* Path matching is prefix-based on a *normalised* absolute path.  We make the
 * normalisation explicit and conservative because a rule that keys on
 * "/etc/shadow" must not be evaded by "/etc//shadow", "./../etc/shadow" or a
 * path opened through a symlink.  Resolution happens where user memory is
 * readable; this API consumes an already-resolved path. */
typedef struct iou_path_pattern {
	const char *prefix;      /* absolute, normalised, no trailing slash      */
	uint32_t len;
	uint8_t  exact;          /* 1 = whole path must equal prefix             */
	uint8_t  is_dir;         /* 1 = prefix names a directory ("prefix/...")  */
} iou_path_pattern_t;

typedef struct iou_rule {
	char *name;              /* operator-visible id ("shadow-read-deny")     */
	iou_verdict_t verdict;
	uint32_t action_mask;    /* which semantic actions it covers             */
	uint32_t eq_syscall;     /* 0 = any; else require this __NR_* (x86_64)   */

	/* Identity filters.  0 means "any".  uids are compared against the
	 * *submitter* euid captured at submit time, not the worker thread. */
	uint32_t uid;            /* matches euid                                  */
	uint32_t gid;            /* matches egid                                  */
	uint32_t tgid;           /* matches the issuer's thread-group id          */

	/* Path filters (both optional).  A rule with path1 set requires the
	 * event to have a path that matches; if the event has no path, it does
	 * not match (no accidental "pathless event satisfies path rule"). */
	iou_path_pattern_t path1;
	iou_path_pattern_t path2;

	/* Opcode restriction; IOU_RULE_OPCODE_ANY for all.  Useful for rules
	 * that specifically target the uring spelling of an operation, e.g.
	 * "deny IORING_OP_URING_CMD from unprivileged processes" -- exactly the
	 * class of thing the existing syscall rules cannot express. */
	uint16_t opcode;         /* IOU_RULE_OPCODE_ANY or 0..255               */

	/* Flags that must be present/absent (IOU_OPF_*). */
	uint32_t require_flags;
	uint32_t forbid_flags;

	/* Ring restriction: 0 = any ring, else only rings with these setup flags
	 * (e.g. require SQPOLL to target the "no visible syscalls at all" case). */
	uint32_t ring_flags_mask;
	uint32_t ring_flags_value;

	uint16_t priority;       /* higher wins when several match              */
	uint8_t  log_only;       /* deny verdict that only records -- for rollout */
} iou_rule_t;

#define IOU_RULE_OPCODE_ANY 0xffffu

/* ------------------------------------------------------------------ */
/* Rule set                                                           */
/* ------------------------------------------------------------------ */

typedef struct iou_ruleset {
	iou_rule_t *rules;
	size_t n_rules;
	size_t cap;
	/* Precomputed: per-action "highest-priority deny" and allow lists to let
	 * the hot path early-out for the overwhelming majority of events. */
	uint32_t deny_action_mask;
	uint32_t alert_action_mask;
	uint32_t allow_action_mask;
	uint32_t total_denies;
	uint32_t total_alerts;
} iou_ruleset_t;

/* Lifecycle. */
bool iou_ruleset_init(iou_ruleset_t *rs);
void iou_ruleset_free(iou_ruleset_t *rs);

/* Add a rule; the ruleset deep-copies `name` and any pattern prefixes.
 * Returns false on allocation failure or nonsense (e.g. deny rule with no
 * action mask and no opcode -- that would deny everything including NOP). */
bool iou_ruleset_add(iou_ruleset_t *rs, const iou_rule_t *r);

/* Load the built-in baseline rule set that mirrors the common syscall IDS
 * configuration (sensitive-file reads, outbound connects, exec-class ops,
 * and the uring-specific escape hatches).  This is what makes the component
 * useful on day one; operators can then add their own rules on top. */
bool iou_ruleset_add_baseline(iou_ruleset_t *rs);

/* ------------------------------------------------------------------ */
/* Evaluation                                                         */
/* ------------------------------------------------------------------ */

typedef struct iou_match {
	iou_verdict_t verdict;
	const iou_rule_t *rule;  /* winning rule, NULL if none matched           */
	size_t rule_index;
	/* Which action in the event triggered the match -- important because an
	 * event can carry several (splice reads and writes, say), and only one
	 * of them may be the forbidden one. */
	iou_action_t matched_action;
} iou_match_t;

/* Evaluate one event.  Deterministic, allocation-free, thread-safe for
 * read-only rulesets.  `resolved_path1/2` are absolute normalised paths for
 * ev->path1/path2 if the caller could resolve them (NULL when it could not,
 * e.g. cross-process or an unresolvable pointer).  When a path is NULL but
 * the event has one, path-scoped *allow* rules do not apply (fail closed)
 * while path-scoped *deny* rules fall back to a weaker identity/action match
 * only if the rule also sets those dimensions -- see iou_rules.c. */
void iou_ruleset_eval(const iou_ruleset_t *rs, const iou_event_t *ev,
		      const char *resolved_path1, const char *resolved_path2,
		      iou_match_t *out);

/* Convenience: evaluate and return just the verdict. */
iou_verdict_t iou_ruleset_verdict(const iou_ruleset_t *rs, const iou_event_t *ev,
				  const char *resolved_path1,
				  const char *resolved_path2);

/* True when the event carries `act` among its semantic actions. */
bool iou_event_has_action(const iou_event_t *ev, iou_action_t act);

/* Lexically canonicalise an absolute path in place: collapse "//", drop "./",
 * and strip a trailing "/".  Does NOT resolve symlinks or ".." (that needs
 * path-walk context this layer does not have).  Returns false if `buf` does not
 * begin with '/'.  Callers that resolve user paths should run this after
 * resolution and before handing the result to iou_ruleset_eval(), so patterns
 * and paths are compared in the same canonical form. */
bool iou_path_canonicalise(char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* IOU_RULES_H */

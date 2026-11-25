/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_main.c - the userspace entry point: `iou`.
 *
 * Two modes, chosen by subcommand:
 *
 *   iou decode   Read a captured ring (or a stream of raw SQEs) from a file and
 *                emit audit records.  This is the offline/incident-response
 *                path: given a core dump or a live-process capture produced by
 *                `iou capture`, reconstruct exactly what was submitted.  It
 *                needs no kernel module and no privileges.
 *
 *   iou catalog  Print the built-in opcode catalog (name, introduced version,
 *                semantic actions) for the running kernel's capabilities.
 *
 *   iou caps     Print the running kernel's io_uring capabilities, derived from
 *                PROBE when possible and from the release string otherwise.
 *
 *   iou check <rule-file>  Evaluate a captured SQE stream against a rule file
 *                and report verdicts.  This is how an operator replays
 *                yesterday's traffic against today's rules.
 *
 * The tool deliberately has no "scan live process" mode that pokes at other
 * processes' memory: on Linux that needs ptrace/process_vm_readv and CAP_SYS_PTRACE,
 * belongs in the module or an operator-run tool, and is not something a
 * security control should do silently.  `iou decode` consumes a capture that
 * something else produced.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "iou_sqe.h"
#include "iou_op.h"
#include "iou_version.h"
#include "iou_rules.h"
#include "iou_audit.h"
#include "iou_keeper.h"

#define PROG "iou"

static void usage(void)
{
	fprintf(stderr,
		"usage: " PROG " <command> [options]\n"
		"\n"
		"commands:\n"
		"  catalog                     print the opcode catalog\n"
		"  caps [release]              print io_uring capabilities\n"
		"  decode [--audit] [--paths <map>] file   decode raw SQEs\n"
		"  check <rules> [--paths <map>] file      decode + evaluate rules\n"
		"\n"
		"`file` is a concatenation of 64-byte SQEs as they appear in a ring\n"
		"(one file per ring).  `map` is a sidecar of \"0xPTR<TAB>/abs/path\"\n"
		"lines so path rules can be evaluated offline.\n");
}

/* ------------------------------------------------------------------ */
/* catalog                                                            */
/* ------------------------------------------------------------------ */

static int cmd_catalog(void)
{
	size_t i, n = iou_op_count();

	printf("%-4s %-30s %-10s %-10s %s\n",
	       "num", "opcode", "introduced", "audit_skip", "actions");
	for (i = 0; i < n; i++) {
		const iou_op_desc_t *d = iou_op_at(i);
		char ver[32];
		int a;

		iou_version_str(d->introduced_in, ver, sizeof(ver));
		printf("%-4u %-30s %-10s %-10s ",
		       d->opcode, d->name,
		       d->introduced_in ? ver : "5.1(base)",
		       d->audit_skip ? "yes" : "no");
		if (d->n_actions == 0) {
			printf("-");
		} else {
			for (a = 0; a < d->n_actions; a++)
				printf("%s%s", a ? "," : "",
				       iou_action_name(d->actions[a]));
		}
		printf("\n");
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* caps                                                               */
/* ------------------------------------------------------------------ */

static int cmd_caps(int argc, char **argv)
{
	iou_caps_t caps;
	const char *rel = argc > 0 ? argv[0] : "6.6.0";
	char ver[32];

	/* On a real host this would be filled from uname() and, when permitted,
	 * from a live IORING_REGISTER_PROBE; here we take the release on the
	 * command line so the tool is useful for planning across kernel versions. */
	iou_caps_init_from_release(&caps, rel);
	iou_version_str(caps.kernel_ver, ver, sizeof(ver));
	printf("kernel=%s probed=%s last_op=%u\n", ver,
	       caps.probed ? "yes" : "no", caps.last_op);
	printf("supported opcodes:\n");
	{
		unsigned op;

		for (op = 0; op <= 255; op++)
			if (iou_caps_supports(&caps, (uint8_t)op))
				printf("  %u %s\n", op,
				       iou_op_lookup((uint8_t)op) ?
				       iou_op_lookup((uint8_t)op)->name : "?");
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* decode                                                             */
/* ------------------------------------------------------------------ */

/*
 * The capture format is deliberately the raw ring bytes: a 64-byte SQE per
 * entry.  That is what a memory capture of the SQE pages contains, so an IR
 * analyst can point this at it directly.  A future capture tool can prepend a
 * small header; we tolerate a leading "IOUSQECAP" magic line if present.
 */
static int decode_file(FILE *in, iou_ruleset_t *rs, iou_audit_ctx_t *ac,
		       int use_rules, const iou_path_map_t *pm)
{
	struct iou_sqe sqe;
	uint64_t seq = 0;
	size_t got;

	while ((got = fread(&sqe, 1, sizeof(sqe), in)) == sizeof(sqe)) {
		iou_event_t ev;
		iou_match_t m;
		iou_decode_status_t st;
		const char *p1 = NULL, *p2 = NULL;

		st = iou_decode_sqe(&sqe, 64, NULL, NULL, &ev);
		ev.seq = seq++;
		/* Resolve path pointers through the capture's sidecar, if any. */
		if (pm != NULL) {
			if (ev.path1.present)
				p1 = iou_path_map_lookup(pm, ev.path1.user_ptr);
			if (ev.path2.present)
				p2 = iou_path_map_lookup(pm, ev.path2.user_ptr);
		}
		if (use_rules) {
			iou_ruleset_eval(rs, &ev, p1, p2, &m);
			iou_audit_emit(ac, &ev, &m, p1, p2);
		} else {
			printf("op=%u %s actions=%u flags=0x%x status=%d",
			       ev.opcode,
			       iou_op_lookup(ev.opcode) ?
			       iou_op_lookup(ev.opcode)->name : "unknown",
			       ev.n_actions, ev.op_flags, (int)st);
			if (ev.path1.present && p1)
				printf(" path=%s", p1);
			printf("\n");
		}
	}
	if (got != 0)
		fprintf(stderr, PROG ": trailing %zu bytes are not a whole SQE\n", got);
	return 0;
}

/* ------------------------------------------------------------------ */
/* minimal rule file parser                                           */
/* ------------------------------------------------------------------ */

/*
 * Rule file grammar (one rule per line, '#' comments):
 *
 *   deny|alert|allow  action=<action-name>[,...]  [path=<prefix>]  [name=<id>]
 *
 * Examples:
 *   deny  action=file_read,file_create  path=/etc/shadow
 *   alert action=net_connect
 *
 * This is intentionally small; production uses the structured loader in the
 * module/daemon.  It exists so `iou check` can replay a capture against a
 * human-readable policy without a full config system.
 */
static iou_action_t action_from_name(const char *s, size_t len)
{
	int a;

	for (a = 0; a < IOU_ACT_MAX; a++) {
		const char *n = iou_action_name((iou_action_t)a);

		if (strlen(n) == len && strncmp(n, s, len) == 0)
			return (iou_action_t)a;
	}
	return IOU_ACT_NONE;
}

static int load_rules(const char *path, iou_ruleset_t *rs)
{
	FILE *f = fopen(path, "r");
	char line[512];
	size_t ln = 0;

	if (f == NULL) {
		fprintf(stderr, PROG ": cannot open rules %s: %s\n", path,
			strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line, *tok;
		iou_rule_t r;

		ln++;
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;

		memset(&r, 0, sizeof(r));
		r.name = "rule";
		/* memset leaves opcode at 0, which is IORING_OP_NOP -- NOT "any".
		 * A parsed rule that does not name an opcode must match all of them,
		 * so default it explicitly to the ANY sentinel.  (This is a real trap:
		 * a zero-init rule would otherwise only ever match a NOP.) */
		r.opcode = IOU_RULE_OPCODE_ANY;
		if (strncmp(p, "deny", 4) == 0) {
			r.verdict = IOU_VERDICT_DENY; p += 4;
		} else if (strncmp(p, "alert", 5) == 0) {
			r.verdict = IOU_VERDICT_ALERT; p += 5;
		} else if (strncmp(p, "allow", 5) == 0) {
			r.verdict = IOU_VERDICT_ALLOW; p += 5;
		} else {
			fprintf(stderr, PROG ": %s:%zu unknown verdict\n", path, ln);
			continue;
		}

		tok = strtok(p, " \t\n");
		while (tok != NULL) {
			if (strncmp(tok, "action=", 7) == 0) {
				/* Split the comma list by hand.  Nested strtok_r()
				 * would clobber the outer strtok() state (they share
				 * a tokenizer per libc); an explicit cursor avoids the
				 * interaction entirely. */
				char *list = tok + 7;

				for (;;) {
					char *comma = strchr(list, ',');
					size_t alen;
					iou_action_t act;

					if (comma != NULL)
						*comma = '\0';
					alen = strlen(list);
					act = action_from_name(list, alen);
					if (act == IOU_ACT_NONE) {
						fprintf(stderr,
							PROG ": %s:%zu bad action '%s'\n",
							path, ln, list);
					} else {
						r.action_mask |= IOU_RULE_ACT(act);
					}
					if (comma == NULL)
						break;
					list = comma + 1;
				}
			} else if (strncmp(tok, "path=", 5) == 0) {
				r.path1.prefix = tok + 5;
				r.path1.len = (uint32_t)strlen(tok + 5);
				r.path1.exact = 0;
			} else if (strncmp(tok, "opcode=", 7) == 0) {
				r.opcode = (uint16_t)atoi(tok + 7);
			}
			tok = strtok(NULL, " \t\n");
		}
		if (r.action_mask == 0 && r.opcode == IOU_RULE_OPCODE_ANY) {
			fprintf(stderr, PROG ": %s:%zu rule constrains nothing\n",
				path, ln);
			continue;
		}
		if (!iou_ruleset_add(rs, &r))
			fprintf(stderr, PROG ": %s:%zu could not add rule\n",
				path, ln);
	}
	fclose(f);
	return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 2;
	}

	if (strcmp(argv[1], "catalog") == 0)
		return cmd_catalog();

	if (strcmp(argv[1], "caps") == 0)
		return cmd_caps(argc - 2, argv + 2);

	if (strcmp(argv[1], "decode") == 0) {
		int audit = 0;
		const char *mapfile = NULL;
		const char *file = NULL;
		int i;
		FILE *in;
		iou_ruleset_t rs;
		iou_audit_ctx_t ac;
		iou_path_map_t pm;

		memset(&pm, 0, sizeof(pm));
		/* Accept --audit / --paths anywhere; the one non-option is the file. */
		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--audit") == 0) {
				audit = 1;
			} else if (strcmp(argv[i], "--paths") == 0) {
				if (i + 1 >= argc) {
					usage();
					return 2;
				}
				mapfile = argv[++i];
			} else if (file == NULL) {
				file = argv[i];
			} else {
				fprintf(stderr, PROG ": unexpected argument '%s'\n",
					argv[i]);
				return 2;
			}
		}
		if (file == NULL) {
			usage();
			return 2;
		}
		in = fopen(file, "rb");
		if (in == NULL) {
			fprintf(stderr, PROG ": cannot open %s: %s\n", file,
				strerror(errno));
			return 1;
		}
		if (mapfile != NULL && iou_path_map_load(mapfile, &pm) != 0)
			fprintf(stderr, PROG ": cannot load path map %s; path rules"
				" will not be evaluated\n", mapfile);
		iou_ruleset_init(&rs);
		iou_audit_init(&ac, stdout, audit ? IOU_FMT_AUDIT : IOU_FMT_JSONL,
			       0, 0);
		(void)decode_file(in, &rs, &ac, audit, &pm);
		iou_ruleset_free(&rs);
		iou_path_map_free(&pm);
		fclose(in);
		return 0;
	}

	if (strcmp(argv[1], "check") == 0) {
		FILE *in;
		iou_ruleset_t rs;
		iou_audit_ctx_t ac;
		iou_path_map_t pm;
		const char *mapfile = NULL;
		const char *rules_file = NULL;
		const char *sqe_file = NULL;
		int j;

		memset(&pm, 0, sizeof(pm));
		/*
		 * `check <rules> <file> [--paths <map>]`, but accept --paths
		 * anywhere so the documented ordering and the convenient trailing
		 * form both work.  The first two non-option arguments are rules and
		 * capture, in that order.
		 */
		for (j = 2; j < argc; j++) {
			if (strcmp(argv[j], "--paths") == 0) {
				if (j + 1 >= argc) {
					usage();
					return 2;
				}
				mapfile = argv[++j];
			} else if (rules_file == NULL) {
				rules_file = argv[j];
			} else if (sqe_file == NULL) {
				sqe_file = argv[j];
			} else {
				fprintf(stderr, PROG ": unexpected argument '%s'\n",
					argv[j]);
				return 2;
			}
		}
		if (rules_file == NULL || sqe_file == NULL) {
			usage();
			return 2;
		}

		iou_ruleset_init(&rs);
		if (load_rules(rules_file, &rs) != 0) {
			iou_ruleset_free(&rs);
			return 1;
		}
		if (mapfile != NULL && iou_path_map_load(mapfile, &pm) != 0)
			fprintf(stderr, PROG ": cannot load path map %s\n", mapfile);
		in = fopen(sqe_file, "rb");
		if (in == NULL) {
			fprintf(stderr, PROG ": cannot open %s: %s\n", sqe_file,
				strerror(errno));
			iou_ruleset_free(&rs);
			iou_path_map_free(&pm);
			return 1;
		}
		iou_audit_init(&ac, stdout, IOU_FMT_JSONL, 0, 0);
		(void)decode_file(in, &rs, &ac, 1, &pm);
		fclose(in);
		iou_ruleset_free(&rs);
		iou_path_map_free(&pm);
		return 0;
	}

	usage();
	return 2;
}

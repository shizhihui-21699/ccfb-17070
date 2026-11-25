/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_audit.c - serialise events for the audit/IDS pipeline.
 */
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "iou_audit.h"
#include "iou_version.h"

bool iou_audit_init(iou_audit_ctx_t *ac, FILE *out, iou_audit_format_t fmt,
		    uint64_t epoch_ms, uint32_t host_id)
{
	if (ac == NULL || out == NULL)
		return false;
	memset(ac, 0, sizeof(*ac));
	ac->out = out;
	ac->fmt = fmt;
	ac->epoch_ms = epoch_ms;
	ac->host_id = host_id;
	return true;
}

/* ------------------------------------------------------------------ */
/* Small helpers (all bounded, no allocation)                         */
/* ------------------------------------------------------------------ */

/* Escape a string for JSON.  Control chars become \uXXXX.  Returns bytes
 * written, or cap when truncated (caller appends "..."). */
static size_t json_escape(char *dst, size_t cap, const char *src)
{
	size_t w = 0;
	const unsigned char *p = (const unsigned char *)src;

	if (cap == 0)
		return 0;
	for (; *p && w + 2 < cap; p++) {
		unsigned char c = *p;

		if (c == '"' || c == '\\') {
			dst[w++] = '\\';
			dst[w++] = (char)c;
		} else if (c == '\n') {
			dst[w++] = '\\'; dst[w++] = 'n';
		} else if (c == '\r') {
			dst[w++] = '\\'; dst[w++] = 'r';
		} else if (c == '\t') {
			dst[w++] = '\\'; dst[w++] = 't';
		} else if (c < 0x20) {
			dst[w++] = '\\'; dst[w++] = 'u';
			dst[w++] = '0'; dst[w++] = '0';
			dst[w++] = (char)('0' + ((c >> 4) & 0xf));
			/* avoid odd literal spellings; build the hex digit */
			dst[w - 1] = (char)('0' + ((c >> 4) & 0xf));
			dst[w++] = (char)((c & 0xf) < 10 ? '0' + (c & 0xf)
							 : 'a' + ((c & 0xf) - 10));
		} else {
			dst[w++] = (char)c;
		}
	}
	dst[w] = '\0';
	return w;
}

static const char *flags_to_str(uint32_t f, char *buf, size_t cap)
{
	size_t w = 0;

	buf[0] = '\0';
	if (f & IOU_OPF_UNKNOWN_OPCODE) {
		w += (size_t)snprintf(buf + w, cap - w, "%sunknown_opcode", w ? "|" : "");
	}
	if (f & IOU_OPF_FUTURE_OPCODE)
		w += (size_t)snprintf(buf + w, cap - w, "%sfuture_opcode", w ? "|" : "");
	if (f & IOU_OPF_NOT_IN_KERNEL)
		w += (size_t)snprintf(buf + w, cap - w, "%snot_in_kernel", w ? "|" : "");
	if (f & IOU_OPF_FIXED_FILE)
		w += (size_t)snprintf(buf + w, cap - w, "%sfixed_file", w ? "|" : "");
	if (f & IOU_OPF_FORCED_ASYNC)
		w += (size_t)snprintf(buf + w, cap - w, "%sforced_async", w ? "|" : "");
	if (f & IOU_OPF_BAD_FLAGS)
		w += (size_t)snprintf(buf + w, cap - w, "%sbad_flags", w ? "|" : "");
	if (f & IOU_OPF_CMD_PASSTHROUGH)
		w += (size_t)snprintf(buf + w, cap - w, "%scmd_passthrough", w ? "|" : "");
	if (f & IOU_OPF_MULTISHOT)
		w += (size_t)snprintf(buf + w, cap - w, "%smultishot", w ? "|" : "");
	if (f & IOU_OPF_CREDS_OVERRIDE)
		w += (size_t)snprintf(buf + w, cap - w, "%screds_override", w ? "|" : "");
	if (buf[0] == '\0')
		return "none";
	return buf;
}

/* ------------------------------------------------------------------ */
/* Offline path map                                                   */
/* ------------------------------------------------------------------ */

static int cmp_entry(const void *a, const void *b)
{
	const iou_path_map_entry_t *x = a, *y = b;

	if (x->user_ptr < y->user_ptr)
		return -1;
	if (x->user_ptr > y->user_ptr)
		return 1;
	return 0;
}

const char *iou_path_map_lookup(const iou_path_map_t *m, uint64_t ptr)
{
	iou_path_map_entry_t key;
	const iou_path_map_entry_t *hit;

	if (m == NULL || m->n == 0 || ptr == 0)
		return NULL;
	/* Entries are sorted at load time for binary search. */
	key.user_ptr = ptr;
	hit = bsearch(&key, m->entries, m->n, sizeof(m->entries[0]), cmp_entry);
	return hit ? hit->path : NULL;
}

void iou_path_map_free(iou_path_map_t *m)
{
	size_t i;

	if (m == NULL)
		return;
	for (i = 0; i < m->n; i++)
		free(m->entries[i].path);
	free(m->entries);
	m->entries = NULL;
	m->n = 0;
}

int iou_path_map_load(const char *filename, iou_path_map_t *out)
{
	FILE *f;
	char line[1024];
	size_t cap = 0;

	if (filename == NULL || out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));
	f = fopen(filename, "r");
	if (f == NULL)
		return -1;

	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line, *tab, *path;
		unsigned long long ptr;
		size_t len;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;
		tab = strchr(p, '\t');
		if (tab == NULL)
			tab = strchr(p, ' ');
		if (tab == NULL)
			continue;
		*tab = '\0';
		path = tab + 1;
		while (*path == ' ' || *path == '\t')
			path++;
		len = strlen(path);
		while (len > 0 && (path[len - 1] == '\n' || path[len - 1] == '\r' ||
				   path[len - 1] == ' '))
			path[--len] = '\0';
		if (len == 0 || path[0] != '/')
			continue;   /* only absolute paths are meaningful */
		/* Cannot tell a bad hex literal from a truncated one with %llx;
		 * use strtoull and require the whole field. */
		{
			char *end = NULL;

			errno = 0;
			ptr = (unsigned long long)strtoull(p, &end, 0);
			if (errno != 0 || end == p || *end != '\0')
				continue;
		}

		if (out->n == cap) {
			size_t ncap = cap ? cap * 2u : 64u;
			iou_path_map_entry_t *ne;

			ne = realloc(out->entries, ncap * sizeof(*ne));
			if (ne == NULL) {
				fclose(f);
				iou_path_map_free(out);
				return -1;
			}
			out->entries = ne;
			cap = ncap;
		}
		out->entries[out->n].path = malloc(len + 1);
		if (out->entries[out->n].path == NULL) {
			fclose(f);
			iou_path_map_free(out);
			return -1;
		}
		memcpy(out->entries[out->n].path, path, len + 1);
		out->entries[out->n].user_ptr = ptr;
		out->n++;
	}
	fclose(f);
	qsort(out->entries, out->n, sizeof(out->entries[0]), cmp_entry);
	return 0;
}

/* ------------------------------------------------------------------ */
/* JSON                                                               */
/* ------------------------------------------------------------------ */

static bool emit_json(iou_audit_ctx_t *ac, const iou_event_t *ev,
		      const iou_match_t *m,
		      const char *r1, const char *r2)
{
	char esc[512];
	char flags[160];
	char ver[32];
	uint8_t i;
	const iou_op_desc_t *d = iou_op_lookup(ev->opcode);

	iou_version_str(ev->op_introduced_in, ver, sizeof(ver));

	fprintf(ac->out,
		"{\"type\":\"%s\",\"seq\":%llu,\"ts_ms\":%llu,"
		"\"pid\":%u,\"tgid\":%u,\"ppid\":%u,"
		"\"uid\":%u,\"euid\":%u,\"fsuid\":%u,"
		"\"gid\":%u,\"egid\":%u,\"fsgid\":%u,",
		IOU_AUDIT_URINGOP == 1336 ? "uringop" : "uringop",
		(unsigned long long)ev->seq,
		(unsigned long long)(ac->epoch_ms + ev->submit_ts_ns / 1000000ull),
		ev->pid, ev->tgid, ev->ppid,
		ev->uid, ev->euid, ev->fsuid,
		ev->gid, ev->egid, ev->fsgid);

	fprintf(ac->out,
		"\"ring_id\":%llu,\"ring_fd\":%d,\"ring_flags\":%d,"
		"\"opcode\":%u,\"opcode_name\":\"%s\",\"op_introduced\":\"%s\","
		"\"sqe_flags\":%u,\"user_data\":%llu,\"fd\":%d,\"len\":%u,"
		"\"off\":%llu,",
		(unsigned long long)ev->ring_id, ev->ring_fd, ev->ring_flags,
		ev->opcode, d ? d->name : "unknown", ver,
		ev->sqe_flags, (unsigned long long)ev->user_data,
		ev->fd, ev->len, (unsigned long long)ev->offset);

	fprintf(ac->out, "\"actions\":[");
	for (i = 0; i < ev->n_actions && i < IOU_MAX_EVENT_ACTIONS; i++)
		fprintf(ac->out, "%s\"%s\"", i ? "," : "",
			iou_action_name(ev->actions[i]));
	fprintf(ac->out, "],");

	fprintf(ac->out, "\"eq_syscalls\":[");
	for (i = 0; i < ev->n_actions && i < IOU_MAX_EVENT_ACTIONS; i++) {
		if (ev->eq_syscall[i] >= 0)
			fprintf(ac->out, "%s%d", i ? "," : "", ev->eq_syscall[i]);
		else
			fprintf(ac->out, "%snull", i ? "," : "");
	}
	fprintf(ac->out, "],");

	fprintf(ac->out, "\"flags\":\"%s\",", flags_to_str(ev->op_flags, flags, sizeof(flags)));

	if (ev->path1.present) {
		json_escape(esc, sizeof(esc), r1 ? r1 : "");
		fprintf(ac->out, "\"path\":\"%s\",\"path_resolved\":%s,\"path_dfd\":%d,",
			esc, r1 ? "true" : "false", ev->path1.dfd);
	}
	if (ev->path2.present) {
		json_escape(esc, sizeof(esc), r2 ? r2 : "");
		fprintf(ac->out, "\"path2\":\"%s\",\"path2_resolved\":%s,",
			esc, r2 ? "true" : "false");
	}

	fprintf(ac->out,
		"\"success\":%s,\"exit\":%lld,\"async\":%s,"
		"\"verdict\":\"%s\",\"rule\":\"%s\",\"matched_action\":\"%s\"}\n",
		(ev->completed && ev->result_errno == 0) ? "true" : (ev->completed ? "false" : "null"),
		(long long)ev->result,
		(ev->op_flags & IOU_OPF_FORCED_ASYNC) ? "true" : "false",
		iou_verdict_name(m ? m->verdict : IOU_VERDICT_ALLOW),
		m && m->rule ? m->rule->name : "",
		iou_action_name(m ? m->matched_action : IOU_ACT_NONE));

	return !ferror(ac->out);
}

/* ------------------------------------------------------------------ */
/* Native audit record                                                */
/* ------------------------------------------------------------------ */

static bool emit_audit(iou_audit_ctx_t *ac, const iou_event_t *ev,
		       const iou_match_t *m,
		       const char *r1, const char *r2)
{
	char flags[160];
	const iou_op_desc_t *d = iou_op_lookup(ev->opcode);

	/*
	 * Same field vocabulary as kernel audit_log_uring() plus the fields
	 * that make an io_uring record usable by a syscall IDS: the
	 * reconstructed syscall family and resolved path.  `iod` identifies the
	 * ring instance so records from one process's several rings can be
	 * correlated (the kernel's own record has no ring identity, which is
	 * why its io_uring records are hard to attribute).
	 */
	fprintf(ac->out,
		"type=%d audit(%llu.%llu:%u): pid=%u uid=%u auid=%u "
		"tgid=%u ppid=%u ses=%u "
		"uring_op=%u op=%s sqe_flags=0x%x async=%d "
		"iod=%llu ring_fd=%d act=%s sys=%d "
		"success=%s exit=%lld "
		"verdict=%s rule=%s flags=%s\n",
		IOU_AUDIT_URINGOP,
		(unsigned long long)(ac->epoch_ms * 1000ull + ev->submit_ts_ns / 1000ull),
		(unsigned long long)ev->seq, ac->host_id,
		ev->pid, ev->uid, ev->uid /* auid unknown to us */,
		ev->tgid, ev->ppid, (unsigned)0,
		ev->opcode, d ? d->name : "unknown", ev->sqe_flags,
		(ev->op_flags & IOU_OPF_FORCED_ASYNC) ? 1 : 0,
		(unsigned long long)ev->ring_id, ev->ring_fd,
		ev->n_actions ? iou_action_name(ev->actions[0]) : "none",
		ev->n_actions ? ev->eq_syscall[0] : -1,
		(ev->completed && ev->result_errno == 0) ? "yes" : "no",
		(long long)ev->result,
		iou_verdict_name(m ? m->verdict : IOU_VERDICT_ALLOW),
		m && m->rule ? m->rule->name : "-",
		flags_to_str(ev->op_flags, flags, sizeof(flags)));

	/*
	 * The path is appended as a separate "name=" field on its own line only
	 * when resolved; auditd parsers treat unknown field=value pairs
	 * gracefully, and an unresolved pointer is never written as if it were a
	 * path.
	 */
	if (ev->path1.present && r1)
		fprintf(ac->out, "type=%d audit(%llu.%llu:%u): name=%s\n",
			IOU_AUDIT_URINGOP,
			(unsigned long long)(ac->epoch_ms * 1000ull + ev->submit_ts_ns / 1000ull),
			(unsigned long long)ev->seq, ac->host_id, r1);
	if (ev->path2.present && r2)
		fprintf(ac->out, "type=%d audit(%llu.%llu:%u): name2=%s\n",
			IOU_AUDIT_URINGOP,
			(unsigned long long)(ac->epoch_ms * 1000ull + ev->submit_ts_ns / 1000ull),
			(unsigned long long)ev->seq, ac->host_id, r2);

	return !ferror(ac->out);
}

bool iou_audit_emit(iou_audit_ctx_t *ac, const iou_event_t *ev,
		    const iou_match_t *match,
		    const char *resolved_path1, const char *resolved_path2)
{
	bool ok;

	if (ac == NULL || ev == NULL || ac->out == NULL)
		return false;

	/* Stamp a sequence number here so every record -- including those the
	 * caller later joins from the CQE -- is globally ordered by the emitter,
	 * not by the (possibly racy) submit timestamp. */
	((iou_event_t *)ev)->seq = ac->next_seq++;

	switch (ac->fmt) {
	case IOU_FMT_JSONL:
		ok = emit_json(ac, ev, match, resolved_path1, resolved_path2);
		break;
	case IOU_FMT_AUDIT:
		ok = emit_audit(ac, ev, match, resolved_path1, resolved_path2);
		break;
	default:
		ok = false;
		break;
	}

	if (!ok)
		ac->lost_events++;
	return ok;
}

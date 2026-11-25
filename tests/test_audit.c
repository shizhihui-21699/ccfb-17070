/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_audit.c - record shape and the attribution contract.
 *
 * The single most important field in these records is the identity of the
 * SUBMITTER, which is what the kernel loses by the time the operation
 * completes on a worker.  These tests assert it survives intact into both
 * output formats, and that hostile path bytes cannot break the record.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iou_audit.h"
#include "iou_op.h"
#include "iou_rules.h"
#include "iou_sqe.h"

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

static iou_event_t mk_event(uint8_t opcode)
{
	struct iou_sqe s;
	iou_event_t e;
	iou_submitter_t w;

	memset(&w, 0, sizeof(w));
	w.pid = w.tid = w.tgid = 4321;
	w.ppid = 1;
	w.uid = 1000;
	w.euid = 1000;
	w.fsuid = 1000;
	w.ring_id = 0xfeedfaceull;
	w.ring_fd = 9;
	w.ring_flags = IOU_SETUP_SQPOLL;

	memset(&s, 0, sizeof(s));
	s.opcode = opcode;
	s.fd = 5;
	s.addr = 0x1234;
	s.len = 256;
	s.user_data = 0xabcdef;

	memset(&e, 0, sizeof(e));
	(void)iou_decode_sqe(&s, 64, NULL, &w, &e);
	e.submit_ts_ns = 5000000ull;  /* 5 ms */
	(void)iou_event_complete(&e, -13, 6000000ull);
	return e;
}

static void test_json_record(void)
{
	iou_event_t e = mk_event(18 /* OPENAT */);
	iou_audit_ctx_t ac;
	iou_match_t m;
	char *buf = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&buf, &len);

	CHECK(f != NULL, "open_memstream");
	CHECK(iou_audit_init(&ac, f, IOU_FMT_JSONL, 1000, 42), "init");
	memset(&m, 0, sizeof(m));
	m.verdict = IOU_VERDICT_DENY;
	m.rule = NULL;
	CHECK(iou_audit_emit(&ac, &e, &m, "/etc/shadow", NULL), "emit");
	fclose(f);

	CHECK(len > 0, "empty record");
	CHECK(strstr(buf, "\"pid\":4321") != NULL, "submitter pid missing");
	CHECK(strstr(buf, "\"tgid\":4321") != NULL, "submitter tgid missing");
	CHECK(strstr(buf, "\"euid\":1000") != NULL, "submitter euid missing");
	CHECK(strstr(buf, "\"ring_id\":") != NULL, "ring id missing");
	CHECK(strstr(buf, "\"opcode_name\":\"IORING_OP_OPENAT\"") != NULL,
	      "opcode name missing");
	CHECK(strstr(buf, "\"actions\":[\"file_create\"]") != NULL,
	      "action missing");
	CHECK(strstr(buf, "\"path\":\"/etc/shadow\"") != NULL, "path missing");
	CHECK(strstr(buf, "\"success\":false") != NULL, "success should be false");
	CHECK(strstr(buf, "\"exit\":-13") != NULL, "exit missing");
	CHECK(strstr(buf, "\"verdict\":\"deny\"") != NULL, "verdict missing");
	/* Exactly one newline: a JSONL sink assumes one object per line. */
	CHECK(buf[len - 1] == '\n' && memchr(buf, '\n', len - 1) == NULL,
	      "record is not exactly one line");
	free(buf);
}

static void test_audit_record(void)
{
	iou_event_t e = mk_event(22 /* READ */);
	iou_audit_ctx_t ac;
	iou_match_t m;
	char *buf = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&buf, &len);

	memset(&m, 0, sizeof(m));
	m.verdict = IOU_VERDICT_ALERT;
	CHECK(iou_audit_init(&ac, f, IOU_FMT_AUDIT, 1000, 42), "init");
	CHECK(iou_audit_emit(&ac, &e, &m, NULL, NULL), "emit");
	fclose(f);

	CHECK(strstr(buf, "type=1336") != NULL, "AUDIT_URINGOP type missing");
	CHECK(strstr(buf, "pid=4321") != NULL, "pid missing");
	CHECK(strstr(buf, "uring_op=22") != NULL, "uring_op missing");
	CHECK(strstr(buf, "verdict=alert") != NULL, "verdict missing");
	CHECK(strstr(buf, "ring_fd=9") != NULL, "ring fd missing");
	free(buf);
}

static void test_path_escaping(void)
{
	/* A path with quotes, control chars and a newline must not break the
	 * record framing: that is the classic log-injection path into an IDS. */
	iou_event_t e = mk_event(18);
	iou_audit_ctx_t ac;
	iou_match_t m;
	char *buf = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&buf, &len);
	const char nasty[] = "/tmp/a\"b\\c\ninjected\x01line";

	memset(&m, 0, sizeof(m));
	iou_audit_init(&ac, f, IOU_FMT_JSONL, 1000, 42);
	CHECK(iou_audit_emit(&ac, &e, &m, nasty, NULL), "emit");
	fclose(f);

	CHECK(buf[len - 1] == '\n' && memchr(buf, '\n', len - 1) == NULL,
	      "escaped path injected a newline into the JSON record");
	CHECK(strstr(buf, "\\\"") != NULL, "quote not escaped");
	CHECK(strstr(buf, "\\n") != NULL, "newline not escaped");
	CHECK(strstr(buf, "\\u0001") != NULL, "control char not escaped");
	free(buf);
}

static void test_unresolved_path_marked(void)
{
	/* When we could not resolve the path, the record must say so rather than
	 * present an empty string as if it were the path. */
	iou_event_t e = mk_event(18);
	iou_audit_ctx_t ac;
	iou_match_t m;
	char *buf = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&buf, &len);

	memset(&m, 0, sizeof(m));
	iou_audit_init(&ac, f, IOU_FMT_JSONL, 1000, 42);
	CHECK(iou_audit_emit(&ac, &e, &m, NULL, NULL), "emit");
	fclose(f);
	CHECK(strstr(buf, "\"path_resolved\":false") != NULL,
	      "unresolved path not marked: %s", buf);
	free(buf);
}

static void test_seq_monotonic(void)
{
	iou_event_t e1 = mk_event(22), e2 = mk_event(22);
	iou_audit_ctx_t ac;
	iou_match_t m;
	FILE *f = fopen("/dev/null", "w");

	memset(&m, 0, sizeof(m));
	iou_audit_init(&ac, f, IOU_FMT_JSONL, 0, 0);
	iou_audit_emit(&ac, &e1, &m, NULL, NULL);
	iou_audit_emit(&ac, &e2, &m, NULL, NULL);
	CHECK(e1.seq + 1 == e2.seq, "seq not monotonic: %llu %llu",
	      (unsigned long long)e1.seq, (unsigned long long)e2.seq);
	fclose(f);
}


static void test_path_map(void)
{
	/* Offline replay: pointer -> path sidecar.  Bad lines must be skipped,
	 * never crash, and lookups must be exact-pointer (no prefix matching). */
	char tmp[] = "/tmp/iou_pathmap_test_XXXXXX";
	int fd = mkstemp(tmp);
	FILE *f;
	iou_path_map_t pm;
	const char *got;

	if (fd < 0) {
		CHECK(0, "mkstemp failed");
		return;
	}
	f = fdopen(fd, "w");
	fputs("# comment\n", f);
	fputs("0xdeadbeef\t/etc/shadow\n", f);
	fputs("0x1111\t/etc//shadow/\n", f);      /* non-canonical but fine */
	fputs("0x2222\tnot/absolute\n", f);      /* relative: skipped */
	fputs("garbage line without tab\n", f);
	fputs("0x3333\n", f);                     /* no path: skipped */
	fclose(f);

	CHECK(iou_path_map_load(tmp, &pm) == 0, "load failed");
	CHECK(pm.n == 2, "expected 2 valid entries, got %zu", pm.n);

	got = iou_path_map_lookup(&pm, 0xdeadbeef);
	CHECK(got && strcmp(got, "/etc/shadow") == 0, "lookup 0xdeadbeef -> %s",
	      got ? got : "(null)");
	CHECK(iou_path_map_lookup(&pm, 0x1111) != NULL, "lookup 0x1111");
	CHECK(iou_path_map_lookup(&pm, 0x2222) == NULL, "relative path must be skipped");
	CHECK(iou_path_map_lookup(&pm, 0xdeadbee0) == NULL, "partial pointer must miss");
	CHECK(iou_path_map_lookup(&pm, 0) == NULL, "null pointer");

	iou_path_map_free(&pm);
	remove(tmp);
}

int main(void)
{
	test_json_record();
	test_audit_record();
	test_path_escaping();
	test_unresolved_path_marked();
	test_seq_monotonic();
	test_path_map();

	printf("test_audit: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}

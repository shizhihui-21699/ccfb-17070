/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_version.c - release parsing and probe-driven capabilities.
 */
#include <stdio.h>
#include <string.h>

#include "iou_op.h"
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

static void test_parse(void)
{
	uint32_t v;

	CHECK(iou_version_parse("6.6.30-200.fc39.x86_64", &v) && v == IOU_VERSION(6, 6),
	      "fedora release");
	CHECK(iou_version_parse("5.15.0-91-generic", &v) && v == IOU_VERSION(5, 15),
	      "ubuntu release");
	CHECK(iou_version_parse("4.18.0-513.5.1.el8_9.x86_64", &v) && v == IOU_VERSION(4, 18),
	      "rhel release");
	CHECK(iou_version_parse("6.1.0-rpi7-rpi-v8", &v) && v == IOU_VERSION(6, 1),
	      "rpi release");
	CHECK(iou_version_parse("5.4", &v) && v == IOU_VERSION(5, 4), "bare");
	CHECK(!iou_version_parse("", &v), "empty");
	CHECK(!iou_version_parse("garbage", &v), "garbage");
	CHECK(!iou_version_parse("5", &v), "no minor");
	CHECK(!iou_version_parse("5.", &v), "trailing dot");
}

static void test_release_supports(void)
{
	iou_caps_t c;

	iou_caps_init_from_release(&c, "6.6.0");
	CHECK(iou_caps_supports(&c, 0), "NOP on 6.6");
	CHECK(iou_caps_supports(&c, 22), "READ on 6.6");
	CHECK(!iou_caps_supports(&c, 56), "BIND must not exist on 6.6");
	CHECK(!iou_caps_supports(&c, 55), "FTRUNCATE (6.9) must not exist on 6.6");

	iou_caps_init_from_release(&c, "6.9.0");
	CHECK(iou_caps_supports(&c, 55), "FTRUNCATE exists on 6.9");

	iou_caps_init_from_release(&c, "5.4.0");
	CHECK(iou_caps_supports(&c, 9), "SENDMSG introduced 5.4");
	CHECK(!iou_caps_supports(&c, 13), "ACCEPT must not exist on 5.4");

	iou_caps_init_from_release(&c, "4.18.0");
	CHECK(!iou_caps_supports(&c, 0), "no io_uring at all on 4.18");
}

static void test_future_and_known(void)
{
	iou_caps_t c;

	iou_caps_init_from_release(&c, "6.16.0");
	CHECK(iou_caps_is_known_number(&c, 62), "62 known on 6.16");
	CHECK(!iou_caps_is_known_number(&c, 200), "200 unknown on 6.16");

	/* Probed caps take precedence: last_op 30 means 31+ are unknown. */
	iou_caps_init_from_release(&c, "6.16.0");
	{
		uint8_t probe[16 + 31 * 8];
		memset(probe, 0, sizeof(probe));
		probe[0] = 30;
		probe[1] = 31;
		iou_caps_apply_probe(&c, probe, sizeof(probe));
	}
	CHECK(!iou_caps_is_known_number(&c, 31), "probe last_op overrides release");
}

static void test_probe_trust_and_bounds(void)
{
	iou_caps_t c;
	uint8_t probe[16 + 10 * 8];

	/* A lying ops_len far larger than the buffer must not be honoured
	 * beyond the bytes we actually have. */
	memset(probe, 0, sizeof(probe));
	iou_caps_init_from_release(&c, "6.6.0");
	probe[0] = 200;
	probe[1] = 255;  /* claims 255 entries, buffer holds 10 */
	/* mark entry 9 supported and consistent */
	probe[16 + 9 * 8 + 0] = 9;
	probe[16 + 9 * 8 + 2] = 1;
	iou_caps_apply_probe(&c, probe, sizeof(probe));
	CHECK(c.probed, "probed");
	CHECK(c.last_op == 200, "last_op honoured");
	CHECK(iou_caps_supports(&c, 9), "entry 9 within buffer honoured");
	/* opcode 60 has no entry (buffer only covers 0..9) so must be unsupported
	 * even though under last_op. */
	CHECK(!iou_caps_supports(&c, 60), "op without a supported bit is unsupported");

	/* A desynchronised array (entry op != index) must be ignored. */
	memset(probe, 0, sizeof(probe));
	probe[0] = 22; probe[1] = 10;
	probe[16 + 5 * 8 + 0] = 99; /* claims opcode 99 lives at slot 5 */
	probe[16 + 5 * 8 + 2] = 1;
	iou_caps_init_from_release(&c, "6.6.0");
	iou_caps_apply_probe(&c, probe, sizeof(probe));
	CHECK(!iou_caps_supports(&c, 99), "desync guard must reject");

	/* A too-short buffer must be a no-op, leaving caps unprobed. */
	iou_caps_init_from_release(&c, "6.6.0");
	iou_caps_apply_probe(&c, probe, 8);
	CHECK(!c.probed, "short probe buffer must not mark probed");
}

static void test_version_str(void)
{
	char b[16];

	iou_version_str(IOU_VERSION(5, 15), b, sizeof(b));
	CHECK(strcmp(b, "5.15") == 0, "str %s", b);
	iou_version_str(0, b, sizeof(b));
	CHECK(strcmp(b, "unknown") == 0, "unknown str %s", b);
}

int main(void)
{
	test_parse();
	test_release_supports();
	test_future_and_known();
	test_probe_trust_and_bounds();
	test_version_str();

	printf("test_version: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}

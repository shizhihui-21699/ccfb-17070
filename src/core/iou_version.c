/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_version.c - release parsing and live capability probing.
 *
 * Release parsing exists only to give operators a familiar "5.15" in output
 * and to seed the pre-probe fallback.  The PROBE result is what enforcement
 * trusts (see iou_version.h for why).
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "iou_op.h"
#include "iou_version.h"

bool iou_version_parse(const char *release, uint32_t *out)
{
	unsigned major = 0, minor = 0, n = 0;
	const char *p = release;

	if (release == NULL || out == NULL)
		return false;
	if (!isdigit((unsigned char)*p))
		return false;

	while (isdigit((unsigned char)*p)) {
		major = major * 10u + (unsigned)(*p - '0');
		if (major > 999u)
			return false;
		p++;
	}
	if (*p != '.')
		return false;
	p++;
	if (!isdigit((unsigned char)*p))
		return false;
	while (isdigit((unsigned char)*p)) {
		minor = minor * 10u + (unsigned)(*p - '0');
		if (minor > 999u)
			return false;
		p++;
		n++;
	}
	if (n == 0)
		return false;
	*out = IOU_VERSION(major, minor);
	return true;
}

const char *iou_version_str(uint32_t v, char *buf, size_t buflen)
{
	if (buf == NULL || buflen == 0)
		return "";
	if (v == 0)
		snprintf(buf, buflen, "unknown");
	else
		snprintf(buf, buflen, "%u.%u", v >> 8, v & 0xffu);
	return buf;
}

void iou_caps_init_from_release(iou_caps_t *caps, const char *release)
{
	uint32_t v = 0;

	if (caps == NULL)
		return;
	memset(caps, 0, sizeof(*caps));
	if (release != NULL && iou_version_parse(release, &v)) {
		caps->kernel_ver = v;
		caps->kernel_major = (uint8_t)(v >> 8);
		caps->kernel_minor = (uint8_t)(v & 0xffu);
	}
}

static void caps_set_supported(iou_caps_t *caps, uint8_t op)
{
	caps->supported[op >> 3] |= (uint8_t)(1u << (op & 7u));
}

static bool caps_get_supported(const iou_caps_t *caps, uint8_t op)
{
	return (caps->supported[op >> 3] & (uint8_t)(1u << (op & 7u))) != 0;
}

void iou_caps_apply_probe(iou_caps_t *caps, const void *probe, size_t bytes)
{
	const uint8_t *p = probe;
	uint8_t last_op, ops_len, i;
	size_t avail;

	if (caps == NULL || probe == NULL || bytes < IOU_PROBE_HDR_SIZE)
		return;

	/*
	 * Layout: u8 last_op; u8 ops_len; u16 resv; u32 resv2[3]; ops[].
	 * The kernel clamps ops_len so the array fits the caller's buffer, but
	 * we must not trust that: a malicious or buggy caller could hand us a
	 * short buffer.  Compute avail from `bytes`, not from ops_len.
	 */
	last_op = p[0];
	ops_len = p[1];

	memset(caps->supported, 0, sizeof(caps->supported));
	caps->last_op = last_op;
	caps->probed = true;

	avail = (bytes - IOU_PROBE_HDR_SIZE) / IOU_PROBE_OP_SIZE;
	if (avail < ops_len)
		ops_len = (uint8_t)avail;

	for (i = 0; i < ops_len; i++) {
		const uint8_t *e = p + IOU_PROBE_HDR_SIZE + (size_t)i * IOU_PROBE_OP_SIZE;
		uint8_t op = e[0];
		uint16_t flags;

		/* e[1] is resv */
		flags = (uint16_t)(e[2] | ((uint16_t)e[3] << 8));
		if (!(flags & IOU_PROBE_OP_SUPPORTED))
			continue;
		/* The array is indexed by opcode from 0, so bit i <-> opcode i; use
		 * the entry's own op byte so a desynchronised array cannot mislabel
		 * an opcode as supported. */
		if (op != i)
			continue;
		caps_set_supported(caps, op);
	}
}

/* ------------------------------------------------------------------ */
/* Release-based hints (fallback / advisory)                           */
/* ------------------------------------------------------------------ */

/*
 * For each opcode: the release that introduced it.  A kernel at version V is
 * assumed to support opcode O iff V >= introduced_in(O).  Entries with
 * introduced_in == 0 (the 5.1 base set) are supported on every kernel that
 * has io_uring at all.
 *
 * This table is a *fallback*, never the authority, because backports and
 * removals both break the inequality in both directions.
 */
static uint32_t release_intro(uint8_t op)
{
	const iou_op_desc_t *d = iou_op_lookup(op);

	if (d == NULL)
		return 0;
	return d->introduced_in;
}

bool iou_caps_may_support(const iou_caps_t *caps, uint8_t opcode)
{
	if (caps == NULL)
		return true; /* no version info: assume yes, decode defensively */
	if (iou_op_lookup(opcode) == NULL)
		return false; /* beyond our catalog */
	if (caps->kernel_ver == 0)
		return true; /* unknown kernel: assume yes */
	if (caps->kernel_ver < IOU_VER_MIN_IOURING)
		return false;
	return caps->kernel_ver >= release_intro(opcode);
}

bool iou_caps_supports(const iou_caps_t *caps, uint8_t opcode)
{
	if (caps == NULL)
		return true;
	if (caps->probed) {
		if (opcode > caps->last_op)
			return false;
		return caps_get_supported(caps, opcode);
	}
	return iou_caps_may_support(caps, opcode);
}

bool iou_caps_is_known_number(const iou_caps_t *caps, uint8_t opcode)
{
	if (caps == NULL)
		return true;
	if (caps->probed)
		return opcode <= caps->last_op;
	if (caps->kernel_ver != 0)
		return iou_caps_may_support(caps, opcode);
	return true;
}

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_version.h - kernel-version handling and authoritative opcode capability
 * probing.
 *
 * THE PROBLEM
 * -----------
 * "Different kernel versions support wildly different operation types."  A
 * static table keyed on release numbers is not enough, for two reasons:
 *
 *   - Enterprise distributions backport io_uring into kernels whose release
 *     number predates the feature (RHEL 8 ships io_uring on a 4.18 base),
 *     and they backport individual opcodes long after upstream.
 *   - Downstream kernels *remove* opcodes (some Android/embedded trees strip
 *     IORING_OP_URING_CMD), and CONFIG gating can make an opcode fail even
 *     when the number is defined.
 *
 * So the release number is only a *hint*.  The authoritative answer is
 * IORING_REGISTER_PROBE, which the kernel answers from its live
 * io_issue_defs[] table:
 *
 *     struct io_uring_probe { u8 last_op; u8 ops_len; ...; ops[]; }
 *     ops[i].flags & IO_URING_OP_SUPPORTED   -> opcode i exists and is wired up
 *
 * iou_caps_t therefore carries both: `kernel_ver` (parsed from uname) for
 * ops' "introduced upstream in" metadata and the advisory/alerting that
 * depends on it, and `supported[]` from the live probe for enforcement
 * decisions.  When probed data exists it always wins.
 */
#ifndef IOU_VERSION_H
#define IOU_VERSION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encode a release as (major << 8) | minor so it compares numerically:
 * 5.4 -> 0x0504, 6.16 -> 0x0610.  Patch level is deliberately ignored: no
 * io_uring ABI change has ever been patch-level. */
#define IOU_VERSION(major, minor) (((uint32_t)(major) << 8) | (uint32_t)(minor))

/* Oldest kernel with any io_uring at all (5.1). */
#define IOU_VER_MIN_IOURING   IOU_VERSION(5, 1)
/* Oldest kernel the decoder + enforcement path is validated against. */
#define IOU_VER_MIN_SUPPORTED IOU_VERSION(5, 4)

#define IOU_CAPS_MAX_OPCODE 255u

typedef struct iou_caps {
	uint32_t kernel_ver;         /* IOU_VERSION(major, minor); 0 if unknown */
	uint8_t  kernel_major;
	uint8_t  kernel_minor;
	uint8_t  last_op;            /* highest opcode the *running kernel* knows */
	bool     probed;             /* supported[] came from a live IORING_REGISTER_PROBE */
	uint8_t  supported[(IOU_CAPS_MAX_OPCODE + 1u + 7u) / 8u];
} iou_caps_t;

/* Parse a release string into IOU_VERSION form.  Accepts what uname -r emits on
 * every distribution we have seen:
 *    "6.6.30-200.fc39.x86_64"        -> 0x0606
 *    "5.15.0-91-generic"             -> 0x050f
 *    "4.18.0-513.5.1.el8_9.x86_64"   -> 0x0412
 *    "6.1.0-rpi7-rpi-v8"             -> 0x0601
 * Returns false (and leaves *out untouched) when the string does not start
 * with "<digits>.<digits>". */
bool iou_version_parse(const char *release, uint32_t *out);

/* Human-readable "5.15" form.  Returns *buf. */
const char *iou_version_str(uint32_t v, char *buf, size_t buflen);

/* Initialise caps from a release string; supported[] stays empty. */
void iou_caps_init_from_release(iou_caps_t *caps, const char *release);

/* Fold in the result of a real IORING_REGISTER_PROBE.  `probe` points at the
 * bytes the kernel wrote; `bytes` is how much of the buffer is valid (the
 * kernel clamps ops_len to what fits).  Only `last_op` and entries whose
 * IO_URING_OP_SUPPORTED bit is set are honoured, so a truncated or hostile
 * buffer cannot mark an opcode supported. */
void iou_caps_apply_probe(iou_caps_t *caps, const void *probe, size_t bytes);

/* Advisory view: does the upstream release support this opcode?  Used for
 * "opcode not yet in this kernel" alerting and for the static catalog. */
bool iou_caps_may_support(const iou_caps_t *caps, uint8_t opcode);

/* Enforcement view.  If probed, the live table is authoritative; otherwise we
 * fall back to the same release-based answer as above. */
bool iou_caps_supports(const iou_caps_t *caps, uint8_t opcode);

/* True when the opcode number is at or below the running kernel's last_op.
 * An SQE whose opcode is *above* last_op is not merely unsupported -- on a
 * kernel that never heard of it, submitting it means the attacker guessed a
 * future opcode, which is worth flagging rather than silently ignoring. */
bool iou_caps_is_known_number(const iou_caps_t *caps, uint8_t opcode);

#ifdef __cplusplus
}
#endif

#endif /* IOU_VERSION_H */

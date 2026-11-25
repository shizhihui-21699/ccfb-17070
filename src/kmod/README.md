# iou_uring kernel module

Two ways to deploy this in-kernel, depending on what you control.

## Path A — tracepoint module (unprivileged, no kernel change)

`iou_kmod_main.c` as written. Loads into any kernel ≥ 5.4 with `CONFIG_IO_URING`,
hooks `io_uring_submit_*` and `io_uring_create`, and drives the same
decode→rules→keeper pipeline the userspace tests exercise. It gives you:

- **full audit** of every submission, with submitter attribution captured at
  submit time (the correlation the kernel loses);
- **per-process escalation state**, driven by unknown-opcode and malformed-SQE
  evidence;
- **enforcement of DENY/DISABLE** *where an LSM gate exists* (6.6+).

It does **not** itself gate anything: a tracepoint cannot veto, and a loadable
module cannot add callbacks to an LSM's `hooks[]` array at runtime. So on a
kernel where the `uring_allowed`/`uring_cmd` LSM hooks are present, pair this
module with Path B's hook bodies; on older kernels you get audit + policy
decisions, not blocks. `iou_keeper` records the shortfall in
`enforce_failures`, and audit records say `enforced_by=none` — the component
never claims a block it did not make.

```sh
make kmod KDIR=/lib/modules/$(uname -r)/build
sudo insmod src/kmod/iou_uring.ko            # monitor only
sudo insmod src/kmod/iou_uring.ko enforce=1  # after baselining
```

## Path B — LSM integration (6.6+)

To make DENY/DISABLE actually block, the two decision functions in
`iou_kmod_main.c` (`iou_decide_ring_setup`, `iou_decide_uring_cmd`) are published
as LSM hooks. The uring LSM hooks were added in 6.6 (`uring_allowed`,
`uring_cmd`, `uring_sqpoll`, `uring_override_creds`) — verified against
`include/linux/lsm_hook_defs.h` and `security/security.c`. Integrate them into an
in-tree LSM (an existing one, or a small new minor LSM) whose `hooks[]` array
lists:

```c
LSM_HOOK_INIT(uring_allowed, iou_decide_ring_setup),
LSM_HOOK_INIT(uring_cmd,     iou_decide_uring_cmd),
```

and have that LSM call into the module's `iou_keeper`/`iou_ruleset` (exported
symbols, or compiled together). This is the supported route: a module cannot do
it alone.

**What each kernel version offers** (all verified against the upstream tree):

| hook | since | effect here |
|---|---|---|
| `uring_allowed` | 6.6 | per-process DISABLE of `io_uring_setup()` |
| `uring_cmd` | — (predates name) | per-process denial of driver passthrough |
| `uring_sqpoll` | — | deny SQPOLL rings (the "no syscall at all" case) |
| `uring_override_creds` | — | gate personality/cred-override usage |

On kernels older than 6.6 there is no `uring_allowed`; the operator-deployable
alternative is `kernel.io_uring_disabled=1` with a `io_uring_group` allow-list
(global, not per-process) combined with this module's audit.

## Honest status

This module is a thin adapter and is **not** built or exercised by the portable
test suite (no kernel tree in that environment). Everything it depends on for
correctness — SQE decoding, opcode catalog, version gating, rule matching,
escalation — lives in `src/core/` and is fully unit-tested. Treat the adapter
as requiring a real-kernel build-and-boot check before production, exactly as
you would any out-of-tree module.

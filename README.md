# iou_uring — audit & intercept io_uring submissions

A C audit component that closes the io_uring blind spot in a syscall-based
intrusion-detection setup. It turns every operation submitted to a kernel
io_uring queue into the same event the existing syscall rules already match,
and can restrict, deny, or disable the interface **per process** — without
breaking the database and storage services that use it for throughput.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full rationale and
[`docs/opcode-catalog.md`](docs/opcode-catalog.md) for the generated opcode
table.

## Quick build & test

```sh
make          # portable library + `iou` CLI, C99, no kernel headers
make test     # unit tests; no root, no kernel required
```

```
== build/test_decode
test_decode: 247 checks, 0 failures
== build/test_version
test_version: 28 checks, 0 failures
== build/test_rules
test_rules: 32 checks, 0 failures
== build/test_ring
test_ring: 33 checks, 0 failures
== build/test_keeper
test_keeper: 20036 checks, 0 failures
== build/test_audit
test_audit: 37 checks, 0 failures
== CLI integration
test_cli: all checks passed
all portable tests passed
```

Kernel module (Linux, requires a kernel tree):

```sh
make kmod KDIR=/lib/modules/$(uname -r)/build
sudo insmod iou_uring.ko            # monitor-only by default
# after baselining:
sudo insmod iou_uring.ko enforce=1
```

## What it does

1. **Sees every submission.** `io_uring_submit_sqe` tracepoint in the module
   (submitter context, exact credentials), or a hardened shared-memory reader
   from userspace where no module can be loaded. Most of the dangerous opcodes
   (`READ`, `OPENAT`, `CONNECT`, `STATX`, `SPLICE`, …) are the ones the kernel's
   own `AUDIT_URINGOP` deliberately skips; this component emits for all of them.

2. **Reconstructs syscall-equivalent events.** Each SQE becomes semantic
   actions (`file_read`, `file_create`, `net_connect`, …) plus the syscall
   family it equals, with the path argument (dfd + pointer) preserved. Policy
   matches these, never opcode numbers — so the same rule covers `openat(2)`,
   `IORING_OP_OPENAT`, and `IORING_OP_OPENAT2`, on any kernel that supports them.

3. **Handles version drift.** A live `IORING_REGISTER_PROBE` decides what the
   running kernel can execute; a release-string fallback covers kernels where
   probing is impossible. An opcode this build does not know **fails closed**
   (alerts unconditionally), so a future kernel cannot silently reopen the blind
   spot.

4. **Attributes completions correctly.** Identity is captured at submit time,
   before the operation moves to a worker thread; the completion CQE is joined
   back by `user_data` + ring id. This is the correlation the kernel loses.

5. **Escalates per process, surgically.** MONITOR → RESTRICT (freeze the opcode
   set to what the workload actually used) → DENY → DISABLE, driven by a pure
   state machine. The database never escalates; a process submitting unknown
   opcodes or malformed SQEs reaches DISABLE in a handful of submissions. When
   the mechanism cannot deliver a rung, the component reports the truth
   (`enforced_by`) instead of pretending.

## CLI

```sh
iou catalog                                       # opcode table
iou caps 6.6                                      # capabilities of a kernel
iou decode capture.sqe                            # decode raw SQEs
iou decode --paths pm.txt capture.sqe             # + resolve path pointers
iou check policy.txt capture.sqe --paths pm.txt   # offline replay vs policy
```

`capture.sqe` is raw ring bytes (64-byte SQEs); `pm.txt` is a
`pointer<TAB>/abs/path` sidecar so path rules evaluate without a live process.

## Layout

| path | what |
|---|---|
| `include/` | portable ABI + interfaces (kernel-header-free, static-asserted) |
| `src/core/` | decode, version/probe, ring reader, rules, keeper, audit — the tested part |
| `src/iou_main.c` | `iou` CLI |
| `src/kmod/` | kernel module: tracepoints + LSM enforcement |
| `tests/` | unit tests for every portable module |

## Scope / limits

Stated fully in `docs/DESIGN.md`; the short version: `IORING_REGISTER_RESTRICTIONS`
cannot be applied to a foreign ring by a third party, so the module enforces
RUNG 1 by gating submissions itself; the userspace reader cannot prove
cross-process attribution (that is what the module is for); `uring_cmd` driver
passthrough is gated wholesale rather than decoded per command.

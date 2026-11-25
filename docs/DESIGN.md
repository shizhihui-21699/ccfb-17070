# io_uring Audit & Interception Component

Closes the io_uring blind spot in syscall-based intrusion detection: it sees
every operation submitted to the kernel through an io_uring submission queue,
reconstructs each one as the syscall-equivalent event the existing IDS rules
already know how to match, and can restrict, deny, or disable the interface
per process when the evidence justifies it — without breaking the database and
storage workloads that depend on io_uring for performance.

## The problem in one paragraph

A syscall-based IDS watches `read`, `openat`, `connect`, `execve` by hooking
the syscall entry points. io_uring bypasses all of that: a program writes an
operation descriptor into a shared-memory queue and nudges the kernel once
(or, with `IORING_SETUP_SQPOLL`, not even that). The kernel then runs the
operation either inline or on a worker thread. The IDS sees one `io_uring_enter`
(or nothing) and none of the `read`/`openat`/`connect` calls that actually
happened. Full compromise path — read `/etc/shadow`, exfiltrate over a socket —
executes with zero monitored syscalls.

Worse, the kernel's own `AUDIT_URINGOP` record only fires for opcodes whose
`io_issue_def` does **not** set `.audit_skip`. From `io_uring/opdef.c`, 28 of
the ~50 opcodes set `audit_skip = 1`, and they are precisely the dangerous
ones: `READV`, `WRITEV`, `FSYNC`, `READ`, `WRITE`, `OPENAT`, `STATX`, `CONNECT`,
`FALLOCATE`, `FADVISE`, `SPLICE`, `TEE`, … So enabling Linux audit does not
close the gap. This component emits the record for every opcode, in the same
shape, plus the reconstructed syscall semantics.

## Three design decisions that carry the whole thing

### 1. Policy is keyed on semantic actions, never on opcode numbers

"Different kernel versions support wildly different operation types" cannot be
solved with a bigger table; opcode numbers drift, get backported, and get
stripped. Instead, every SQE is decomposed into semantic actions:

```
FILE_READ FILE_WRITE FILE_CREATE FILE_DELETE FILE_RENAME FILE_META FILE_XATTR
NET_CONNECT NET_LISTEN NET_ACCEPT NET_SEND NET_RECV
PROC_WAIT IPC WAIT FS_CONTROL
```

each carrying the syscall family it equals (`openat`, `unlinkat`, `connect`, …).
Rules are written against those actions, so a rule that means "deny reading
`/etc/shadow`" fires identically whether the attacker used `openat(2)` or
`IORING_OP_OPENAT` — and fires for an opcode that exists on the target kernel
regardless of which upstream release introduced it.

`introduced_in` in the catalog (verified against the uapi headers of 29 kernel
tags, v5.1–v6.19) is metadata for docs and alerting only. It is **never** used
to make an enforcement decision. The authoritative answer for "does this kernel
support opcode N" is a live `IORING_REGISTER_PROBE`, folded into `iou_caps_t`.
A release string is the fallback when probing is impossible.

### 2. Attribution is captured at submit time, not at completion

The hard part called out in the brief — "operations execute asynchronously in
kernel threads, hard to correlate back to the initiating process." At issue
time, an operation runs on an io-wq worker or the SQPOLL kthread; `current`
is the worker, and the submitting process is gone. This is why the kernel's own
io_uring audit records are hard to attribute.

The kernel module hooks `io_uring_submit_sqe`/`io_uring_submit_req`, which still
runs in the **submitter's** task context, so pid/tgid/uid/euid/fsuid are the
attacker's. It records them on the event *before* the operation is issued. The
completion CQE is joined back to the event by `user_data` + ring id, so the audit
record carries both submit identity and completion result. The userspace ring
reader (`src/core/iou_ring.c`) sees the same SQE bytes but cannot be trusted for
identity across a foreign process, so it is the fallback where no module can be
loaded.

### 3. Enforcement escalates per process, and the escalation is pure

The brief says "disable this interface for the process when necessary" and, in
the same breath, that databases lean on it heavily. Blanket
`kernel.io_uring_disabled=2` breaks the workload. So enforcement is a four-rung
ladder keyed per tgid (`src/core/iou_keeper.c`):

| Rung | Name | Effect | Mechanism |
|---|---|---|---|
| 0 | MONITOR | audit only, nothing blocked | default; safe on day one |
| 1 | RESTRICT | ring keeps working, opcode set frozen to what was observed | `IORING_REGISTER_RESTRICTIONS` (in-ring) or kmod request gate |
| 2 | DENY | all submissions refused | kmod hook / LSM `uring_cmd` |
| 3 | DISABLE | no new rings; existing rings restricted then cancelled | LSM `uring_allowed` (6.6+) or `io_uring_setup` gate |

RUNG 1 is the surgical one: freeze the union of opcodes the process legitimately
used during an observation window (`learn_window_ns`, default 5 s), then install
that as an allow-list. A database doing `READ`/`WRITE`/`FSYNC` keeps full speed;
an `OPENAT` or `CONNECT` appearing afterward is refused with `-EACCES`. An
allow-list, not a deny-list, because a future kernel's new opcode must default
to *not permitted*.

The escalation decision is a pure function of observed evidence — no syscalls,
no I/O in `iou_keeper.c` — so an auditor can answer "why did the system block
this database" from the code alone. The mechanism that applies a rung is
separate and reports what it *actually* applied (`enforced_by`), never what the
policy wished for.

## Architecture

```
      attacker / database                              audit pipeline
              │                                             ▲
   io_uring_enter / SQPOLL                          AUDIT_URINGOP + JSON
              │                                             │
   ┌──────────▼───────────┐   ┌─────────────┐   ┌───────────┴──────────┐
   │ kernel: submit/issue │──▶│  decode SQE │──▶│  rules + keeper      │
   │  (kmod tracepoint,   │   │  → semantic │   │  → verdict, rung     │
   │   or userspace ring  │   │    actions  │   │                      │
   │   reader)            │   └─────────────┘   └───────────┬──────────┘
   └──────────────────────┘                                 │
                                              ┌─────────────▼──────────┐
                                              │ enforce: restrict/deny │
                                              │ /disable (per process) │
                                              └────────────────────────┘
```

The security logic (decode, rules, keeper) is portable C99, includes no kernel
headers, and is unit-tested on any POSIX host. The kernel module and the
userspace CLI are thin adapters. That split is deliberate: the part that can be
gotten wrong is the part that runs in tests.

## Layout

```
include/        portable ABI + interfaces (no kernel headers)
  iou_sqe.h       byte-exact io_uring SQE/params/CQE mirror, static-asserted
  iou_op.h        opcode catalog + event/semantic-action model
  iou_version.h   release parsing + live PROBE capability model
  iou_rules.h     syscall-equivalent rule engine
  iou_keeper.h    escalation state machine + restriction payload builder
  iou_audit.h     AUDIT_URINGOP / JSONL emitter + offline path map
src/core/       portable implementation (the tested part)
src/iou_main.c  userspace CLI: catalog / caps / decode / check
src/kmod/       kernel module (tracepoints + LSM enforcement)
tests/          unit tests for every portable module
docs/           this file + generated opcode catalog
```

## Build and test

```sh
make            # portable lib + userspace CLI
make test       # run all unit tests (no root, no kernel needed)
make kmod KDIR=/lib/modules/$(uname -r)/build   # kernel module (Linux)
```

The portable suite covers 6 test binaries plus a CLI integration test, ~20 k
checks in all: SQE decoding and hostile-input handling, version/probe gating,
rule matching across syscall/uring spellings, ring parsing under corrupt shared
memory, keeper escalation (including the "database never escalates" regression),
and audit record shape and log-injection resistance.

## CLI

```sh
iou catalog                     # opcode table with introduced version + actions
iou caps 6.6                    # what a given kernel can execute
iou decode capture.sqe          # one line per SQE
iou check rules.txt capture.sqe --paths paths.txt   # replay against policy
```

A capture is a concatenation of 64-byte SQEs (raw ring bytes), optionally paired
with a `pointer<TAB>path` sidecar so path rules evaluate offline. This is the
incident-response path: point it at a memory capture without a module.

## Deployment notes

- **Start in monitor mode.** The module defaults to `enforce=false`. Run a
  monitoring window, watch which processes would have escalated and why
  (`iou_keeper_describe`), then enable enforcement with thresholds that fit the
  fleet.
- **The database is protected by design.** In monitor mode nothing is blocked.
  In enforce mode a well-behaved workload only ever reaches RUNG 1, which
  freezes the opcodes it already uses. Escalation to 2/3 requires unknown
  opcodes or malformed SQEs — which a healthy service does not produce.
- **Version range.** Tested ABI model from 5.1 (first io_uring) through 6.19.
  `uring_allowed` LSM exists 6.6+; on older kernels the module falls back to an
  `io_uring_setup` gate and refuses to claim DISABLE it cannot deliver.
- **Unknown opcodes fail closed.** An opcode outside the catalog raises ALERT
  regardless of the rule table. This is the guarantee that a future kernel
  cannot reintroduce the blind spot this component exists to close.

## Known limits (stated plainly)

- `IORING_REGISTER_RESTRICTIONS` can only be installed by the ring owner on its
  own fd; a third party cannot apply it to another process's ring, even
  in-kernel. The module therefore enforces RUNG 1 by gating submissions itself
  (equivalent effect, revocable). The payload builder in `iou_keeper.c` is for
  the in-process/agents case.
- The userspace reader cannot prove attribution across a foreign process; that
  is what the module is for. Where neither is deployable, the component still
  audits submissions but marks identity as unverified.
- `uring_cmd` (driver passthrough — NVMe admin, ublk, …) reaches operations with
  no syscall-level semantics at all; it is classified FS_CONTROL and gated
  wholesale, not decoded per-command.

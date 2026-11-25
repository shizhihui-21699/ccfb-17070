# io_uring opcode catalog

Generated from the built-in catalog (`iou catalog`).

- **introduced** — upstream release that first defined the opcode,
  checked against the uapi headers of kernel tags v5.1..v6.19.
  Advisory only: enforcement uses a live `IORING_REGISTER_PROBE`.
- **audit_skip** — the kernel suppresses its own `AUDIT_URINGOP`
  record for this opcode (from `io_uring/opdef.c`). These are the
  operations a syscall-based IDS cannot see today.
- **actions** — semantic classes the decoder derives; rules match on
  these, not on opcode numbers.

| # | opcode | introduced | kernel-audited | actions | equivalent |
|---|--------|------------|----------------|---------|------------|
| 0 | `IORING_OP_NOP` | 5.1 | no | — | — |
| 1 | `IORING_OP_READV` | 5.1 | no | file_read | `readv` |
| 2 | `IORING_OP_WRITEV` | 5.1 | no | file_write | `writev` |
| 3 | `IORING_OP_FSYNC` | 5.1 | no | file_meta | `fsync` |
| 4 | `IORING_OP_READ_FIXED` | 5.1 | no | file_read | `read` |
| 5 | `IORING_OP_WRITE_FIXED` | 5.1 | no | file_write | `write` |
| 6 | `IORING_OP_POLL_ADD` | 5.1 | no | wait | — |
| 7 | `IORING_OP_POLL_REMOVE` | 5.1 | yes | — | — |
| 8 | `IORING_OP_SYNC_FILE_RANGE` | 5.2 | no | file_meta | `sync_file_range` |
| 9 | `IORING_OP_SENDMSG` | 5.4 | yes | net_send | `sendmsg` |
| 10 | `IORING_OP_RECVMSG` | 5.4 | yes | net_recv | `recvmsg` |
| 11 | `IORING_OP_TIMEOUT` | 5.4 | no | — | — |
| 12 | `IORING_OP_TIMEOUT_REMOVE` | 5.19 | no | — | — |
| 13 | `IORING_OP_ACCEPT` | 5.19 | yes | net_accept | `accept4` |
| 14 | `IORING_OP_ASYNC_CANCEL` | 5.19 | no | — | — |
| 15 | `IORING_OP_LINK_TIMEOUT` | 5.19 | no | — | — |
| 16 | `IORING_OP_CONNECT` | 5.19 | yes | net_connect | `connect` |
| 17 | `IORING_OP_FALLOCATE` | 5.19 | yes | file_meta | `fallocate` |
| 18 | `IORING_OP_OPENAT` | 5.19 | yes | file_create | `openat` |
| 19 | `IORING_OP_CLOSE` | 5.19 | yes | file_meta | `close` |
| 20 | `IORING_OP_FILES_UPDATE` | 5.19 | no | — | — |
| 21 | `IORING_OP_STATX` | 5.19 | no | file_meta | `statx` |
| 22 | `IORING_OP_READ` | 5.19 | no | file_read | `read` |
| 23 | `IORING_OP_WRITE` | 5.19 | no | file_write | `write` |
| 24 | `IORING_OP_FADVISE` | 5.19 | no | file_meta | `fadvise64` |
| 25 | `IORING_OP_MADVISE` | 5.19 | no | file_meta | `madvise` |
| 26 | `IORING_OP_SEND` | 5.19 | yes | net_send | `sendto` |
| 27 | `IORING_OP_RECV` | 5.19 | yes | net_recv | `recvfrom` |
| 28 | `IORING_OP_OPENAT2` | 5.19 | yes | file_create | `openat2` |
| 29 | `IORING_OP_EPOLL_CTL` | 5.19 | no | — | — |
| 30 | `IORING_OP_SPLICE` | 5.19 | no | file_write, file_read | `splice` |
| 31 | `IORING_OP_PROVIDE_BUFFERS` | 5.19 | no | — | — |
| 32 | `IORING_OP_REMOVE_BUFFERS` | 5.19 | no | — | — |
| 33 | `IORING_OP_TEE` | 5.19 | no | file_write, file_read | `tee` |
| 34 | `IORING_OP_SHUTDOWN` | 5.19 | yes | net_send | `shutdown` |
| 35 | `IORING_OP_RENAMEAT` | 5.19 | yes | file_rename | `renameat2` |
| 36 | `IORING_OP_UNLINKAT` | 5.19 | yes | file_delete | `unlinkat` |
| 37 | `IORING_OP_MKDIRAT` | 5.19 | yes | file_create | `mkdirat` |
| 38 | `IORING_OP_SYMLINKAT` | 5.19 | yes | file_create | `symlinkat` |
| 39 | `IORING_OP_LINKAT` | 5.19 | yes | file_rename | `linkat` |
| 40 | `IORING_OP_MSG_RING` | 5.19 | yes | ipc | — |
| 41 | `IORING_OP_FSETXATTR` | 5.19 | yes | file_xattr | `fsetxattr` |
| 42 | `IORING_OP_SETXATTR` | 5.19 | yes | file_xattr | `setxattr` |
| 43 | `IORING_OP_FGETXATTR` | 5.19 | yes | file_xattr | `fgetxattr` |
| 44 | `IORING_OP_GETXATTR` | 5.19 | yes | file_xattr | `getxattr` |
| 45 | `IORING_OP_SOCKET` | 5.19 | no | net_connect | `socket` |
| 46 | `IORING_OP_URING_CMD` | 5.19 | yes | fs_control | — |
| 47 | `IORING_OP_SEND_ZC` | 6.0 | no | net_send | `sendto` |
| 48 | `IORING_OP_SENDMSG_ZC` | 6.1 | yes | net_send | `sendmsg` |
| 49 | `IORING_OP_READ_MULTISHOT` | 6.7 | yes | file_read | `read` |
| 50 | `IORING_OP_WAITID` | 6.7 | yes | proc_wait | `waitid` |
| 51 | `IORING_OP_FUTEX_WAIT` | 6.7 | yes | ipc | `futex` |
| 52 | `IORING_OP_FUTEX_WAKE` | 6.7 | yes | ipc | `futex` |
| 53 | `IORING_OP_FUTEX_WAITV` | 6.7 | yes | ipc | `futex` |
| 54 | `IORING_OP_FIXED_FD_INSTALL` | 6.8 | yes | file_meta | `fcntl` |
| 55 | `IORING_OP_FTRUNCATE` | 6.9 | yes | file_meta | `ftruncate` |
| 56 | `IORING_OP_BIND` | 6.11 | yes | net_connect | `bind` |
| 57 | `IORING_OP_LISTEN` | 6.11 | yes | net_listen | `listen` |
| 58 | `IORING_OP_RECV_ZC` | 6.15 | yes | net_recv | `recvfrom` |
| 59 | `IORING_OP_EPOLL_WAIT` | 6.15 | no | wait | — |
| 60 | `IORING_OP_READV_FIXED` | 6.15 | no | file_read | `readv` |
| 61 | `IORING_OP_WRITEV_FIXED` | 6.15 | no | file_write | `writev` |
| 62 | `IORING_OP_PIPE` | 6.16 | yes | file_create | `pipe2` |

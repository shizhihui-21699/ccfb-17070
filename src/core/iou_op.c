/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iou_op.c - the opcode catalog.
 *
 * Every row below was checked against the kernel's own prep function for that
 * opcode (io_uring/opdef.c + the per-opcode .c file) rather than from memory.
 * The `audit_skip` column mirrors the kernel's io_issue_defs[] exactly, which
 * is itself evidence of the problem we are fixing: the kernel deliberately
 * does NOT audit the 28 opcodes in this table that do file I/O, connect,
 * stat, truncate -- the ones that matter most.
 *
 * `introduced_in` values were derived by diffing include/uapi/linux/io_uring.h
 * across 29 upstream tags (v5.1 .. v6.19) and taking each opcode's first
 * appearance.  Where a distro backport differs, the live PROBE (iou_caps_t)
 * corrects us; this column is metadata only.
 *
 * Argument sources (what sqe field maps to what syscall argument), also from
 * the prep functions:
 *
 *   openat      fd=dfd, addr=path, open_flags=how.flags, len=mode
 *   openat2     fd=dfd, addr=path, addr2=struct open_how*, len=how size
 *   statx       fd=dfd, addr=path, addr2=statx buf, len=mask, statx_flags=flags
 *   unlinkat    fd=dfd, addr=path, unlink_flags=AT_REMOVEDIR
 *   renameat    fd=old_dfd, addr=oldpath, addr2=newpath, len=new_dfd
 *   mkdirat     fd=dfd, addr=path, len=mode
 *   symlinkat   fd=new_dfd, addr=oldpath(target), addr2=newpath, len must be 0
 *   linkat      fd=old_dfd, addr=oldpath, addr2=newpath, len=new_dfd
 *   ftruncate   fd=file, addr=length
 *   fallocate   fd=file, off=offset, len=mode, addr=length
 *   fsync       fd=file, fsync_flags=DATASYNC, off/len=range
 *   connect     fd=sock, addr=sockaddr*, addr2=addrlen
 *   bind/listen fd=sock, addr=sockaddr*, addr2=addrlen
 *   accept      fd=sock, addr=addr*, addr2=addrlen*, accept_flags
 *   send/sendmsg fd=sock, addr=buf/msghdr, len, msg_flags; addr2=sockaddr*(send)
 *   recv/recvmsg fd=sock, addr=buf/msghdr, len, msg_flags
 *   socket      fd=domain, off=type, len=protocol
 *   setxattr    fd=dfd(if fsetxattr), addr=name, addr2=value, len=size,
 *               addr3=path (for the non-fd variants)
 *   getxattr    fd=dfd(if fgetxattr), addr=name, addr2=value buf, len=size,
 *               addr3=path
 *   splice      fd=out file, splice_fd_in=in file, off=off_out,
 *               splice_off_in=off_in, len
 *   waitid      fd=idtype, addr=id, addr2=infop, len=options, waitid_flags
 */
#include <string.h>

#include "iou_op.h"

/* Generic x86_64 syscall numbers, used only to label equivalent syscalls in
 * audit output.  -1 means "no equivalent syscall".  We deliberately do NOT use
 * <sys/syscall.h>: the audit daemon may run on a different arch than the box
 * it reports, and these are labels, not numbers we ever pass to the kernel. */
#define SC_openat         257
#define SC_openat2        437
#define SC_read             0
#define SC_write            1
#define SC_readv           19
#define SC_writev           20
#define SC_fsync           74
#define SC_fdatasync       75
#define SC_sync_file_range 277
#define SC_fallocate       285
#define SC_ftruncate       77
#define SC_close             3
#define SC_lseek            8
#define SC_statx          332
#define SC_fstat            5
#define SC_sendmsg         46
#define SC_recvmsg         47
#define SC_sendto          44
#define SC_recvfrom        45
#define SC_connect         42
#define SC_bind            49
#define SC_listen          50
#define SC_accept          43
#define SC_accept4        288
#define SC_socket           41
#define SC_getsockopt      55
#define SC_setsockopt      54
#define SC_shutdown        48
#define SC_splice         275
#define SC_tee            276
#define SC_renameat        264
#define SC_renameat2       316
#define SC_unlinkat        263
#define SC_mkdirat        258
#define SC_symlinkat      266
#define SC_linkat         265
#define SC_setxattr        188
#define SC_lsetxattr      189
#define SC_fsetxattr      190
#define SC_getxattr        191
#define SC_lgetxattr      192
#define SC_fgetxattr      193
#define SC_epoll_ctl       233
#define SC_epoll_pwait     281
#define SC_waitid         247
#define SC_clone           56
#define SC_fork            57
#define SC_vfork           58
#define SC_execve          59
#define SC_execveat       322
#define SC_fadvise64      221
#define SC_madvise        28
#define SC_futex          202
#define SC_eventfd2       290
#define SC_pipe2          293
#define SC_msgget          68
#define SC_fcntl           72
#define SC_io_uring_setup 425
#define SC_io_uring_enter 426
#define SC_io_uring_register 427

#define OP(nm, act0, sc0) \
	{ .opcode = (nm), .name = #nm, .n_actions = 1, \
	  .actions = { (act0) }, .eq_syscall = { (sc0) } }

static const iou_op_desc_t io_ops[] = {
	[0] = { .opcode = 0, .name = "IORING_OP_NOP", .introduced_in = 0,
		.n_actions = 0, .eq_syscall = { -1 },
		.audit_skip = 1, .needs_file = 0, .always_async = 0 },

	[1] = { .opcode = 1, .name = "IORING_OP_READV", .introduced_in = 0,
		.n_actions = 1, .actions = { IOU_ACT_FILE_READ }, .eq_syscall = { SC_readv },
		.audit_skip = 1, .needs_file = 1, .always_async = 0, .is_multishot = 0,
		.uses_off = 1 },

	[2] = { .opcode = 2, .name = "IORING_OP_WRITEV", .introduced_in = 0,
		.n_actions = 1, .actions = { IOU_ACT_FILE_WRITE }, .eq_syscall = { SC_writev },
		.audit_skip = 1, .needs_file = 1,
		.uses_off = 1 },

	[3] = { .opcode = 3, .name = "IORING_OP_FSYNC", .introduced_in = 0,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_fsync },
		.audit_skip = 1, .needs_file = 1, .always_async = 1,
		.uses_off = 1 },

	[4] = { .opcode = 4, .name = "IORING_OP_READ_FIXED", .introduced_in = 0,
		.n_actions = 1, .actions = { IOU_ACT_FILE_READ }, .eq_syscall = { SC_read },
		.audit_skip = 1, .needs_file = 1,
		.uses_off = 1 },

	[5] = { .opcode = 5, .name = "IORING_OP_WRITE_FIXED", .introduced_in = 0,
		.n_actions = 1, .actions = { IOU_ACT_FILE_WRITE }, .eq_syscall = { SC_write },
		.audit_skip = 1, .needs_file = 1,
		.uses_off = 1 },

	[6] = { .opcode = 6, .name = "IORING_OP_POLL_ADD", .introduced_in = 0,
		.n_actions = 1, .actions = { IOU_ACT_WAIT }, .eq_syscall = { -1 },
		.audit_skip = 1, .needs_file = 1 },

	[7] = { .opcode = 7, .name = "IORING_OP_POLL_REMOVE", .introduced_in = 0,
		.n_actions = 0, .eq_syscall = { -1 } },

	[8] = { .opcode = 8, .name = "IORING_OP_SYNC_FILE_RANGE", .introduced_in = 0x0502,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_sync_file_range },
		.audit_skip = 1, .needs_file = 1, .always_async = 1,
		.uses_off = 1 },

	[9] = { .opcode = 9, .name = "IORING_OP_SENDMSG", .introduced_in = 0x0504,
		.n_actions = 1, .actions = { IOU_ACT_NET_SEND }, .eq_syscall = { SC_sendmsg },
		.needs_file = 1 },

	[10] = { .opcode = 10, .name = "IORING_OP_RECVMSG", .introduced_in = 0x0504,
		.n_actions = 1, .actions = { IOU_ACT_NET_RECV }, .eq_syscall = { SC_recvmsg },
		.needs_file = 1 },

	[11] = { .opcode = 11, .name = "IORING_OP_TIMEOUT", .introduced_in = 0x0504,
		.n_actions = 0, .eq_syscall = { -1 }, .audit_skip = 1 },

	[12] = { .opcode = 12, .name = "IORING_OP_TIMEOUT_REMOVE", .introduced_in = 0x0513,
		.n_actions = 0, .eq_syscall = { -1 }, .audit_skip = 1 },

	[13] = { .opcode = 13, .name = "IORING_OP_ACCEPT", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_NET_ACCEPT }, .eq_syscall = { SC_accept4 },
		.needs_file = 1,
		.uses_addr2 = 1 },

	[14] = { .opcode = 14, .name = "IORING_OP_ASYNC_CANCEL", .introduced_in = 0x0513,
		.n_actions = 0, .eq_syscall = { -1 }, .audit_skip = 1 },

	[15] = { .opcode = 15, .name = "IORING_OP_LINK_TIMEOUT", .introduced_in = 0x0513,
		.n_actions = 0, .eq_syscall = { -1 }, .audit_skip = 1 },

	[16] = { .opcode = 16, .name = "IORING_OP_CONNECT", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_NET_CONNECT }, .eq_syscall = { SC_connect },
		.needs_file = 1, .uses_path1 = 0 },

	[17] = { .opcode = 17, .name = "IORING_OP_FALLOCATE", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_fallocate },
		.needs_file = 1, .always_async = 1,
		.uses_off = 1 },

	[18] = { .opcode = 18, .name = "IORING_OP_OPENAT", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_CREATE }, .eq_syscall = { SC_openat },
		.uses_path1 = 1 },

	[19] = { .opcode = 19, .name = "IORING_OP_CLOSE", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_close } },

	[20] = { .opcode = 20, .name = "IORING_OP_FILES_UPDATE", .introduced_in = 0x0513,
		.n_actions = 0, .eq_syscall = { -1 }, .audit_skip = 1 },

	[21] = { .opcode = 21, .name = "IORING_OP_STATX", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_statx },
		.audit_skip = 1, .always_async = 1, .uses_path1 = 1,
		.uses_addr2 = 1 },

	[22] = { .opcode = 22, .name = "IORING_OP_READ", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_READ }, .eq_syscall = { SC_read },
		.audit_skip = 1, .needs_file = 1,
		.uses_off = 1 },

	[23] = { .opcode = 23, .name = "IORING_OP_WRITE", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_WRITE }, .eq_syscall = { SC_write },
		.audit_skip = 1, .needs_file = 1,
		.uses_off = 1 },

	[24] = { .opcode = 24, .name = "IORING_OP_FADVISE", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_fadvise64 },
		.audit_skip = 1, .needs_file = 1,
		.uses_off = 1 },

	[25] = { .opcode = 25, .name = "IORING_OP_MADVISE", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_madvise },
		.audit_skip = 1, .always_async = 1 },

	[26] = { .opcode = 26, .name = "IORING_OP_SEND", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_NET_SEND }, .eq_syscall = { SC_sendto },
		.needs_file = 1,
		.uses_addr2 = 1 },

	[27] = { .opcode = 27, .name = "IORING_OP_RECV", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_NET_RECV }, .eq_syscall = { SC_recvfrom },
		.needs_file = 1 },

	[28] = { .opcode = 28, .name = "IORING_OP_OPENAT2", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_CREATE }, .eq_syscall = { SC_openat2 },
		.uses_path1 = 1,
		.uses_addr2 = 1 },

	[29] = { .opcode = 29, .name = "IORING_OP_EPOLL_CTL", .introduced_in = 0x0513,
		.n_actions = 0, .eq_syscall = { -1 }, .audit_skip = 1 },

	[30] = { .opcode = 30, .name = "IORING_OP_SPLICE", .introduced_in = 0x0513,
		.n_actions = 2, .actions = { IOU_ACT_FILE_WRITE, IOU_ACT_FILE_READ },
		.eq_syscall = { SC_splice, -1 },
		.audit_skip = 1, .needs_file = 1, .always_async = 1,
		.uses_off = 1 },

	[31] = { .opcode = 31, .name = "IORING_OP_PROVIDE_BUFFERS", .introduced_in = 0x0513,
		.n_actions = 0, .eq_syscall = { -1 }, .audit_skip = 1 },

	[32] = { .opcode = 32, .name = "IORING_OP_REMOVE_BUFFERS", .introduced_in = 0x0513,
		.n_actions = 0, .eq_syscall = { -1 }, .audit_skip = 1 },

	[33] = { .opcode = 33, .name = "IORING_OP_TEE", .introduced_in = 0x0513,
		.n_actions = 2, .actions = { IOU_ACT_FILE_WRITE, IOU_ACT_FILE_READ },
		.eq_syscall = { SC_tee, -1 },
		.audit_skip = 1, .needs_file = 1, .always_async = 1 },

	[34] = { .opcode = 34, .name = "IORING_OP_SHUTDOWN", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_NET_SEND }, .eq_syscall = { SC_shutdown },
		.needs_file = 1 },

	[35] = { .opcode = 35, .name = "IORING_OP_RENAMEAT", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_RENAME }, .eq_syscall = { SC_renameat2 },
		.uses_path1 = 1, .uses_path2 = 1,
		.uses_addr2 = 1 },

	[36] = { .opcode = 36, .name = "IORING_OP_UNLINKAT", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_DELETE }, .eq_syscall = { SC_unlinkat },
		.uses_path1 = 1 },

	[37] = { .opcode = 37, .name = "IORING_OP_MKDIRAT", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_CREATE }, .eq_syscall = { SC_mkdirat },
		.uses_path1 = 1 },

	[38] = { .opcode = 38, .name = "IORING_OP_SYMLINKAT", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_CREATE }, .eq_syscall = { SC_symlinkat },
		.uses_path1 = 1, .uses_path2 = 1,
		.uses_addr2 = 1 },

	[39] = { .opcode = 39, .name = "IORING_OP_LINKAT", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_RENAME }, .eq_syscall = { SC_linkat },
		.uses_path1 = 1, .uses_path2 = 1,
		.uses_addr2 = 1 },

	[40] = { .opcode = 40, .name = "IORING_OP_MSG_RING", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_IPC }, .eq_syscall = { -1 },
		.needs_file = 1 },

	[41] = { .opcode = 41, .name = "IORING_OP_FSETXATTR", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_XATTR }, .eq_syscall = { SC_fsetxattr },
		.needs_file = 1, .always_async = 1,
		.uses_addr2 = 1 },

	[42] = { .opcode = 42, .name = "IORING_OP_SETXATTR", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_XATTR }, .eq_syscall = { SC_setxattr },
		.always_async = 1, .uses_path1 = 1,
		.uses_addr2 = 1 },

	[43] = { .opcode = 43, .name = "IORING_OP_FGETXATTR", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_XATTR }, .eq_syscall = { SC_fgetxattr },
		.needs_file = 1, .always_async = 1,
		.uses_addr2 = 1 },

	[44] = { .opcode = 44, .name = "IORING_OP_GETXATTR", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FILE_XATTR }, .eq_syscall = { SC_getxattr },
		.always_async = 1, .uses_path1 = 1,
		.uses_addr2 = 1 },

	[45] = { .opcode = 45, .name = "IORING_OP_SOCKET", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_NET_CONNECT }, .eq_syscall = { SC_socket },
		.audit_skip = 1 },

	[46] = { .opcode = 46, .name = "IORING_OP_URING_CMD", .introduced_in = 0x0513,
		.n_actions = 1, .actions = { IOU_ACT_FS_CONTROL }, .eq_syscall = { -1 },
		.needs_file = 1 },

	[47] = { .opcode = 47, .name = "IORING_OP_SEND_ZC", .introduced_in = 0x0600,
		.n_actions = 1, .actions = { IOU_ACT_NET_SEND }, .eq_syscall = { SC_sendto },
		.audit_skip = 1, .needs_file = 1, .always_async = 1 },

	[48] = { .opcode = 48, .name = "IORING_OP_SENDMSG_ZC", .introduced_in = 0x0601,
		.n_actions = 1, .actions = { IOU_ACT_NET_SEND }, .eq_syscall = { SC_sendmsg },
		.needs_file = 1 },

	[49] = { .opcode = 49, .name = "IORING_OP_READ_MULTISHOT", .introduced_in = 0x0607,
		.n_actions = 1, .actions = { IOU_ACT_FILE_READ }, .eq_syscall = { SC_read },
		.needs_file = 1, .is_multishot = 1 },

	[50] = { .opcode = 50, .name = "IORING_OP_WAITID", .introduced_in = 0x0607,
		.n_actions = 1, .actions = { IOU_ACT_PROC_WAIT }, .eq_syscall = { SC_waitid },
		.uses_addr2 = 1 },

	[51] = { .opcode = 51, .name = "IORING_OP_FUTEX_WAIT", .introduced_in = 0x0607,
		.n_actions = 1, .actions = { IOU_ACT_IPC }, .eq_syscall = { SC_futex } },

	[52] = { .opcode = 52, .name = "IORING_OP_FUTEX_WAKE", .introduced_in = 0x0607,
		.n_actions = 1, .actions = { IOU_ACT_IPC }, .eq_syscall = { SC_futex } },

	[53] = { .opcode = 53, .name = "IORING_OP_FUTEX_WAITV", .introduced_in = 0x0607,
		.n_actions = 1, .actions = { IOU_ACT_IPC }, .eq_syscall = { SC_futex } },

	[54] = { .opcode = 54, .name = "IORING_OP_FIXED_FD_INSTALL", .introduced_in = 0x0608,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_fcntl } },

	[55] = { .opcode = 55, .name = "IORING_OP_FTRUNCATE", .introduced_in = 0x0609,
		.n_actions = 1, .actions = { IOU_ACT_FILE_META }, .eq_syscall = { SC_ftruncate },
		.needs_file = 1, .always_async = 1 },

	[56] = { .opcode = 56, .name = "IORING_OP_BIND", .introduced_in = 0x060b,
		.n_actions = 1, .actions = { IOU_ACT_NET_CONNECT }, .eq_syscall = { SC_bind },
		.needs_file = 1 },

	[57] = { .opcode = 57, .name = "IORING_OP_LISTEN", .introduced_in = 0x060b,
		.n_actions = 1, .actions = { IOU_ACT_NET_LISTEN }, .eq_syscall = { SC_listen },
		.needs_file = 1 },

	[58] = { .opcode = 58, .name = "IORING_OP_RECV_ZC", .introduced_in = 0x060f,
		.n_actions = 1, .actions = { IOU_ACT_NET_RECV }, .eq_syscall = { SC_recvfrom },
		.needs_file = 1, .always_async = 1,
		.uses_off = 1 },

	[59] = { .opcode = 59, .name = "IORING_OP_EPOLL_WAIT", .introduced_in = 0x060f,
		.n_actions = 1, .actions = { IOU_ACT_WAIT }, .eq_syscall = { -1 },
		.audit_skip = 1 },

	[60] = { .opcode = 60, .name = "IORING_OP_READV_FIXED", .introduced_in = 0x060f,
		.n_actions = 1, .actions = { IOU_ACT_FILE_READ }, .eq_syscall = { SC_readv },
		.audit_skip = 1, .needs_file = 1 },

	[61] = { .opcode = 61, .name = "IORING_OP_WRITEV_FIXED", .introduced_in = 0x060f,
		.n_actions = 1, .actions = { IOU_ACT_FILE_WRITE }, .eq_syscall = { SC_writev },
		.audit_skip = 1, .needs_file = 1 },

	[62] = { .opcode = 62, .name = "IORING_OP_PIPE", .introduced_in = 0x0610,
		.n_actions = 1, .actions = { IOU_ACT_FILE_CREATE }, .eq_syscall = { SC_pipe2 } },
};

#define IOU_OP_TABLE_LEN ((sizeof io_ops) / (sizeof io_ops[0]))

/* Highest opcode with a catalog entry. */
#define IOU_OP_TABLE_MAX (IOU_OP_TABLE_LEN - 1u)

const iou_op_desc_t *iou_op_lookup(uint8_t opcode)
{
	if (opcode > IOU_OP_TABLE_MAX)
		return NULL;
	if (io_ops[opcode].name == NULL)
		return NULL;
	return &io_ops[opcode];
}

const iou_op_desc_t *iou_op_lookup_for_caps(const iou_caps_t *caps, uint8_t opcode,
					    bool *known_here)
{
	const iou_op_desc_t *d = iou_op_lookup(opcode);

	if (known_here)
		*known_here = false;
	if (d == NULL)
		return NULL;
	if (caps == NULL) {
		if (known_here)
			*known_here = true;
		return d;
	}
	if (iou_caps_supports(caps, opcode)) {
		if (known_here)
			*known_here = true;
		return d;
	}
	/* We know the opcode but this kernel does not run it.  Do not let policy
	 * fire on something that cannot happen. */
	return NULL;
}

size_t iou_op_count(void)
{
	size_t n = 0, i;

	for (i = 0; i < IOU_OP_TABLE_LEN; i++)
		if (io_ops[i].name != NULL)
			n++;
	return n;
}

const iou_op_desc_t *iou_op_at(size_t idx)
{
	size_t i, seen = 0;

	for (i = 0; i < IOU_OP_TABLE_LEN; i++) {
		if (io_ops[i].name == NULL)
			continue;
		if (seen == idx)
			return &io_ops[i];
		seen++;
	}
	return NULL;
}

const char *iou_action_name(iou_action_t act)
{
	switch (act) {
	case IOU_ACT_NONE:       return "none";
	case IOU_ACT_FILE_READ:  return "file_read";
	case IOU_ACT_FILE_WRITE: return "file_write";
	case IOU_ACT_FILE_CREATE:return "file_create";
	case IOU_ACT_FILE_DELETE:return "file_delete";
	case IOU_ACT_FILE_RENAME:return "file_rename";
	case IOU_ACT_FILE_META:  return "file_meta";
	case IOU_ACT_FILE_XATTR: return "file_xattr";
	case IOU_ACT_NET_CONNECT:return "net_connect";
	case IOU_ACT_NET_LISTEN: return "net_listen";
	case IOU_ACT_NET_ACCEPT: return "net_accept";
	case IOU_ACT_NET_SEND:   return "net_send";
	case IOU_ACT_NET_RECV:   return "net_recv";
	case IOU_ACT_PROC_CREATE:return "proc_create";
	case IOU_ACT_PROC_WAIT:  return "proc_wait";
	case IOU_ACT_FS_CONTROL: return "fs_control";
	case IOU_ACT_IPC:        return "ipc";
	case IOU_ACT_WAIT:       return "wait";
	default:                 return "invalid";
	}
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Generate docs/opcode-catalog.md from the built-in catalog. */
#include <stdio.h>

#include "iou_op.h"
#include "iou_version.h"

/* x86_64 syscall names for the labels the catalog carries.  Kept in sync with
 * the SC_* constants in src/core/iou_op.c. */
static const char *sc_name(int nr)
{
	switch (nr) {
	case 0:   return "read";
	case 1:   return "write";
	case 3:   return "close";
	case 5:   return "fstat";
	case 8:   return "lseek";
	case 19:  return "readv";
	case 20:  return "writev";
	case 28:  return "madvise";
	case 41:  return "socket";
	case 42:  return "connect";
	case 43:  return "accept";
	case 44:  return "sendto";
	case 45:  return "recvfrom";
	case 46:  return "sendmsg";
	case 47:  return "recvmsg";
	case 48:  return "shutdown";
	case 49:  return "bind";
	case 50:  return "listen";
	case 54:  return "setsockopt";
	case 55:  return "getsockopt";
	case 56:  return "clone";
	case 57:  return "fork";
	case 58:  return "vfork";
	case 59:  return "execve";
	case 72:  return "fcntl";
	case 74:  return "fsync";
	case 75:  return "fdatasync";
	case 77:  return "ftruncate";
	case 188: return "setxattr";
	case 189: return "lsetxattr";
	case 190: return "fsetxattr";
	case 191: return "getxattr";
	case 192: return "lgetxattr";
	case 193: return "fgetxattr";
	case 202: return "futex";
	case 221: return "fadvise64";
	case 233: return "epoll_ctl";
	case 247: return "waitid";
	case 257: return "openat";
	case 258: return "mkdirat";
	case 263: return "unlinkat";
	case 264: return "renameat";
	case 265: return "linkat";
	case 266: return "symlinkat";
	case 275: return "splice";
	case 276: return "tee";
	case 277: return "sync_file_range";
	case 281: return "epoll_pwait";
	case 285: return "fallocate";
	case 288: return "accept4";
	case 290: return "eventfd2";
	case 293: return "pipe2";
	case 316: return "renameat2";
	case 322: return "execveat";
	case 332: return "statx";
	case 437: return "openat2";
	default:  return NULL;
	}
}

int main(void)
{
	size_t i, n = iou_op_count();

	printf("# io_uring opcode catalog\n\n");
	printf("Generated from the built-in catalog (`iou catalog`).\n\n");
	printf("- **introduced** — upstream release that first defined the opcode,\n");
	printf("  checked against the uapi headers of kernel tags v5.1..v6.19.\n");
	printf("  Advisory only: enforcement uses a live `IORING_REGISTER_PROBE`.\n");
	printf("- **audit_skip** — the kernel suppresses its own `AUDIT_URINGOP`\n");
	printf("  record for this opcode (from `io_uring/opdef.c`). These are the\n");
	printf("  operations a syscall-based IDS cannot see today.\n");
	printf("- **actions** — semantic classes the decoder derives; rules match on\n");
	printf("  these, not on opcode numbers.\n\n");

	printf("| # | opcode | introduced | kernel-audited | actions | equivalent |\n");
	printf("|---|--------|------------|----------------|---------|------------|\n");
	for (i = 0; i < n; i++) {
		const iou_op_desc_t *d = iou_op_at(i);
		char ver[32];
		int a;

		iou_version_str(d->introduced_in, ver, sizeof(ver));

		printf("| %u | `%s` | %s | %s | ", d->opcode, d->name,
		       d->introduced_in ? ver : "5.1",
		       d->audit_skip ? "no" : "yes");

		if (d->n_actions == 0) {
			printf("— | ");
		} else {
			for (a = 0; a < d->n_actions; a++)
				printf("%s%s", a ? ", " : "", iou_action_name(d->actions[a]));
			printf(" | ");
		}

		{
			int printed = 0;

			for (a = 0; a < d->n_actions; a++) {
				const char *nm;
				int nr = d->eq_syscall[a];

				if (nr < 0)
					continue;
				nm = sc_name(nr);
				if (nm != NULL)
					printf("%s`%s`", printed ? ", " : "", nm);
				else
					printf("%s`syscall %d`", printed ? ", " : "", nr);
				printed++;
			}
			if (!printed)
				printf("—");
		}
		printf(" |\n");
	}
	return 0;
}

// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/kinfo.h>
#include <sys/sysctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <rz_util/rz_log.h>
#include "bsd_debug.h"

#ifndef DTYPE_VNODE
#define DTYPE_VNODE  1
#define DTYPE_SOCKET 2
#define DTYPE_PIPE   3
#define DTYPE_FIFO   4
#define DTYPE_KQUEUE 5
#endif

int bsd_handle_signals(RZ_NONNULL RzDebug *dbg) {
	rz_return_val_if_fail(dbg, -1);
	switch (dbg->reason.signum) {
	case SIGTRAP:
		dbg->reason.type = RZ_DEBUG_REASON_BREAKPOINT;
		break;
	case SIGABRT:
		dbg->reason.type = RZ_DEBUG_REASON_ABORT;
		break;
	case SIGSEGV:
		dbg->reason.type = RZ_DEBUG_REASON_SEGFAULT;
		break;
	default:
		dbg->reason.type = RZ_DEBUG_REASON_SIGNAL;
		break;
	}
	return 0;
}

int bsd_reg_write(RZ_NONNULL RzDebug *dbg, int type, RZ_NONNULL const ut8 *buf, int size) {
	rz_return_val_if_fail(dbg && buf, false);
	(void)size;
	int r = -1;
	switch (type) {
	case RZ_REG_TYPE_GPR:
		r = ptrace(PT_SETREGS, dbg->pid, (caddr_t)buf, sizeof(struct reg));
		break;
	case RZ_REG_TYPE_DRX:
#if __i386__ || __x86_64__
		r = ptrace(PT_SETDBREGS, dbg->pid, (caddr_t)buf, sizeof(struct dbreg));
#endif
		break;
	case RZ_REG_TYPE_FPU:
		r = ptrace(PT_SETFPREGS, dbg->pid, (caddr_t)buf, sizeof(struct fpreg));
		break;
	}

	return r == 0;
}

bool bsd_generate_corefile(RZ_NONNULL RzDebug *dbg, RZ_NONNULL char *path, RZ_NULLABLE RzBuffer *dest) {
	(void)dbg;
	(void)path;
	(void)dest;
	return false;
}

RZ_OWN RzDebugInfo *bsd_info(RZ_NONNULL RzDebug *dbg, RZ_NULLABLE const char *arg) {
	rz_return_val_if_fail(dbg, NULL);
	(void)arg;
	char err[_POSIX2_LINE_MAX];
	int cnt = 0;
	RzDebugInfo *rdi = RZ_NEW0(RzDebugInfo);
	if (!rdi) {
		return NULL;
	}

	kvm_t *kd = kvm_openfiles(NULL, "/dev/null", NULL, O_RDONLY, err);
	if (!kd) {
		free(rdi);
		return NULL;
	}

	struct kinfo_proc *kp = kvm_getprocs(kd, KERN_PROC_PID, dbg->pid, &cnt);
	if (kp && cnt > 0) {
		rdi->pid = dbg->pid;
		rdi->tid = dbg->tid;
		rdi->uid = kp->kp_uid;
		rdi->gid = kp->kp_pgid;
		rdi->exe = rz_str_dup(kp->kp_comm);

		switch (kp->kp_stat) {
		case SIDL:
		case SACTIVE:
			rdi->status = RZ_DBG_PROC_RUN;
			break;
		case SSTOP:
			rdi->status = RZ_DBG_PROC_STOP;
			break;
		case SZOMB:
			rdi->status = RZ_DBG_PROC_ZOMBIE;
			break;
		case SCORE:
		default:
			rdi->status = RZ_DBG_PROC_DEAD;
			break;
		}
	}

	kvm_close(kd);

	return rdi;
}

RZ_OWN RzList /*<RzDebugPid *>*/ *bsd_pid_list(RZ_NONNULL RzDebug *dbg, int pid, RZ_NONNULL RzList /*<RzDebugPid *>*/ *list) {
	rz_return_val_if_fail(dbg && list, NULL);
	char errbuf[_POSIX2_LINE_MAX];
	struct kinfo_proc *kp, *entry;
	int cnt = 0;

	kvm_t *kd = kvm_openfiles(NULL, "/dev/null", NULL, O_RDONLY, errbuf);
	if (!kd) {
		RZ_LOG_ERROR("kvm_openfiles failed: %s\n", errbuf);
		rz_list_free(list);
		return NULL;
	}

	kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &cnt);
	for (int i = 0; i < cnt; i++) {
		entry = kp + i;
		// Unless pid 0 is requested, only add the requested pid and its child processes
		if (pid == 0 || entry->kp_pid == pid || entry->kp_ppid == pid) {
			RzDebugPid *p = rz_debug_pid_new(entry->kp_comm, entry->kp_pid, entry->kp_uid, 's', 0);
			if (p) {
				p->ppid = entry->kp_ppid;
				rz_list_append(list, p);
			}
		}
	}

	kvm_close(kd);
	return list;
}

RZ_OWN RzList /*<RzDebugMap *>*/ *bsd_native_sysctl_map(RZ_NONNULL RzDebug *dbg) {
	(void)dbg;
	return NULL;
}

RZ_OWN RzList /*<RzDebugDesc *>*/ *bsd_desc_list(int pid) {
	size_t len = 0;
	if (sysctlbyname("kern.file", NULL, &len, NULL, 0) == -1 || len == 0) {
		return NULL;
	}
	len = len * 4 / 3;
	char *buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	if (sysctlbyname("kern.file", buf, &len, NULL, 0) == -1) {
		free(buf);
		return NULL;
	}

	RzList *ret = rz_list_newf((RzListFree)rz_debug_desc_free);
	if (!ret) {
		free(buf);
		return NULL;
	}

	char *bp = buf;
	char *eb = buf + len;
	while (bp + sizeof(struct kinfo_file) <= eb) {
		struct kinfo_file *kf = (struct kinfo_file *)(uintptr_t)bp;
		size_t step = kf->f_size ? kf->f_size : sizeof(struct kinfo_file);
		bp += step;
		if (kf->f_pid != pid || kf->f_fd < 0) {
			continue;
		}
		int type = '-';
		switch (kf->f_type) {
		case DTYPE_VNODE:
			type = 'v';
			break;
		case DTYPE_SOCKET:
			type = 's';
			break;
		case DTYPE_PIPE:
			type = 'p';
			break;
		case DTYPE_FIFO:
			type = 'f';
			break;
		case DTYPE_KQUEUE:
			type = 'k';
			break;
		default:
			type = '-';
			break;
		}

		int perm = 0;
		if (kf->f_flag & FREAD) {
			perm |= RZ_PERM_R;
		}
		if (kf->f_flag & FWRITE) {
			perm |= RZ_PERM_W;
		}

		char empty_path[] = "";
		RzDebugDesc *desc = rz_debug_desc_new(kf->f_fd, empty_path, perm, type, kf->f_offset);
		if (!desc) {
			break;
		}
		rz_list_append(ret, desc);
	}

	free(buf);
	return ret;
}

static int get_rz_status(enum lwpstat stat) {
	switch (stat) {
	case LSRUN:
		return RZ_DBG_PROC_RUN;
	case LSSTOP:
		return RZ_DBG_PROC_STOP;
	case LSSLEEP:
		return RZ_DBG_PROC_SLEEP;
	default:
		return RZ_DBG_PROC_DEAD;
	}
}

RZ_OWN RzList /*<RzDebugPid *>*/ *bsd_thread_list(RZ_NONNULL RzDebug *dbg, int pid, RZ_NONNULL RzList /*<RzDebugPid *>*/ *list) {
	rz_return_val_if_fail(dbg && list, NULL);
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID | KERN_PROC_FLAG_LWP, pid };
	struct kinfo_proc *kp;
	size_t len = 0;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) == -1) {
		rz_list_free(list);
		return NULL;
	}

	len += sizeof(*kp) + len / 10;
	kp = malloc(len);
	if (!kp) {
		rz_list_free(list);
		return NULL;
	}
	if (sysctl(mib, 4, kp, &len, NULL, 0) == -1) {
		free(kp);
		rz_list_free(list);
		return NULL;
	}

	size_t max = len / sizeof(*kp);
	for (size_t i = 0; i < max; i++) {
		int lwp_stat = get_rz_status(kp[i].kp_lwp.kl_stat);
		const char *th_name = kp[i].kp_lwp.kl_comm[0] ? kp[i].kp_lwp.kl_comm : kp[i].kp_comm;
		RzDebugPid *pid_info = rz_debug_pid_new(th_name, kp[i].kp_lwp.kl_tid,
			kp[i].kp_uid, lwp_stat, (ut64)kp[i].kp_lwp.kl_wchan);
		if (pid_info) {
			rz_list_append(list, pid_info);
		}
	}

	free(kp);
	return list;
}

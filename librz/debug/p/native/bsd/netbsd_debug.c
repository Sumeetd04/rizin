// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/lwp.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <uvm/uvm_param.h>
#include <kvm.h>
#include <limits.h>
#include <rz_util/rz_log.h>
#include "bsd_debug.h"

int bsd_handle_signals(RZ_NONNULL RzDebug *dbg) {
	rz_return_val_if_fail(dbg, -1);
	struct ptrace_siginfo sinfo = { 0 };
	if (ptrace(PT_GET_SIGINFO, dbg->pid, (void *)&sinfo, sizeof(sinfo)) == -1) {
		if (errno == ESRCH) {
			dbg->reason.type = RZ_DEBUG_REASON_DEAD;
			return 0;
		}
		rz_sys_perror("ptrace PTRACE_GET_SIGINFO");
		return -1;
	}

	siginfo_t siginfo = sinfo.psi_siginfo;
	dbg->reason.type = RZ_DEBUG_REASON_SIGNAL;
	dbg->reason.signum = siginfo.si_signo;

	switch (dbg->reason.signum) {
	case SIGABRT:
		dbg->reason.type = RZ_DEBUG_REASON_ABORT;
		break;
	case SIGSEGV:
		dbg->reason.type = RZ_DEBUG_REASON_SEGFAULT;
		break;
	case SIGTRAP:
		if (siginfo.si_code == TRAP_BRKPT) {
			dbg->reason.type = RZ_DEBUG_REASON_BREAKPOINT;
		}
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
		r = ptrace(PT_SETREGS, dbg->pid, (void *)buf, sizeof(struct reg));
		break;
	case RZ_REG_TYPE_DRX:
#if __i386__ || __x86_64__
		r = ptrace(PT_SETDBREGS, dbg->pid, (void *)buf, sizeof(struct dbreg));
#endif
		break;
	case RZ_REG_TYPE_FPU:
		r = ptrace(PT_SETFPREGS, dbg->pid, (void *)buf, sizeof(struct fpreg));
		break;
	}

	return r == 0;
}

bool bsd_generate_corefile(RZ_NONNULL RzDebug *dbg, RZ_NONNULL char *path, RZ_NULLABLE RzBuffer *dest) {
	rz_return_val_if_fail(dbg && path, false);
	(void)dest;
	return ptrace(PT_DUMPCORE, dbg->pid, path, strlen(path)) != -1;
}

RZ_OWN RzDebugInfo *bsd_info(RZ_NONNULL RzDebug *dbg, RZ_NULLABLE const char *arg) {
	rz_return_val_if_fail(dbg, NULL);
	(void)arg;
	struct kinfo_proc2 *kp;
	char err[_POSIX2_LINE_MAX];
	int np;
	RzDebugInfo *rdi = RZ_NEW0(RzDebugInfo);
	if (!rdi) {
		return NULL;
	}

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, err);
	if (!kd) {
		free(rdi);
		return NULL;
	}

	kp = kvm_getproc2(kd, KERN_PROC_PID, dbg->pid, sizeof(*kp), &np);
	if (kp && np > 0) {
		rdi->pid = dbg->pid;
		rdi->tid = dbg->tid;
		rdi->uid = kp->p_uid;
		rdi->gid = kp->p__pgid;
		rdi->exe = rz_str_dup(kp->p_comm);

		switch (kp->p_stat) {
		case SDEAD:
			rdi->status = RZ_DBG_PROC_DEAD;
			break;
		case SSTOP:
			rdi->status = RZ_DBG_PROC_STOP;
			break;
		case SZOMB:
			rdi->status = RZ_DBG_PROC_ZOMBIE;
			break;
		case SACTIVE:
		case SIDL:
		case SDYING:
			rdi->status = RZ_DBG_PROC_RUN;
			break;
		default:
			rdi->status = RZ_DBG_PROC_SLEEP;
			break;
		}
	}

	kvm_close(kd);

	return rdi;
}

RZ_OWN RzList /*<RzDebugPid *>*/ *bsd_pid_list(RZ_NONNULL RzDebug *dbg, int pid, RZ_NONNULL RzList /*<RzDebugPid *>*/ *list) {
	rz_return_val_if_fail(dbg && list, NULL);
	char errbuf[_POSIX2_LINE_MAX];
	struct kinfo_proc2 *kp, *entry;
	int cnt = 0;

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
	if (!kd) {
		RZ_LOG_ERROR("kvm_openfiles failed: %s\n", errbuf);
		rz_list_free(list);
		return NULL;
	}

	kp = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &cnt);
	for (int i = 0; i < cnt; i++) {
		entry = kp + i;
		// Unless pid 0 is requested, only add the requested pid and its child processes
		if (pid == 0 || entry->p_pid == pid || entry->p_ppid == pid) {
			RzDebugPid *p = rz_debug_pid_new(entry->p_comm, entry->p_pid, entry->p_uid, 's', 0);
			if (p) {
				p->ppid = entry->p_ppid;
				rz_list_append(list, p);
			}
		}
	}

	kvm_close(kd);
	return list;
}

RZ_OWN RzList /*<RzDebugMap *>*/ *bsd_native_sysctl_map(RZ_NONNULL RzDebug *dbg) {
	rz_return_val_if_fail(dbg, NULL);
	int mib[5] = { CTL_VM, VM_PROC, VM_PROC_MAP, dbg->pid, sizeof(struct kinfo_vmentry) };
	size_t len = 0;

	if (sysctl(mib, 5, NULL, &len, NULL, 0) == -1 || len == 0) {
		return NULL;
	}
	len = len * 4 / 3;
	struct kinfo_vmentry *kve = malloc(len);
	if (!kve) {
		return NULL;
	}
	if (sysctl(mib, 5, kve, &len, NULL, 0) == -1) {
		free(kve);
		return NULL;
	}

	RzList *list = rz_debug_map_list_new();
	if (!list) {
		free(kve);
		return NULL;
	}

	size_t count = len / sizeof(struct kinfo_vmentry);
	int unk = 0;
	for (size_t i = 0; i < count; i++) {
		int perm = 0;
		if (kve[i].kve_protection & KVME_PROT_READ) {
			perm |= RZ_PERM_R;
		}
		if (kve[i].kve_protection & KVME_PROT_WRITE) {
			perm |= RZ_PERM_W;
		}
		if (kve[i].kve_protection & KVME_PROT_EXEC) {
			perm |= RZ_PERM_X;
		}

		char unk_name[32];
		char *name = kve[i].kve_path;
		if (!*name) {
			snprintf(unk_name, sizeof(unk_name), "unk%d", unk++);
			name = unk_name;
		}

		RzDebugMap *map = rz_debug_map_new(name, kve[i].kve_start, kve[i].kve_end, perm, 0);
		if (!map) {
			break;
		}
		map->offset = kve[i].kve_offset;
		map->file = rz_str_dup(name);
		rz_list_append(list, map);
	}

	free(kve);
	return list;
}

static RZ_OWN RzList /*<RzDebugDesc *>*/ *netbsd_sysctl_desc_list(int pid) {
	int mib[6] = { CTL_KERN, KERN_FILE2, KERN_FILE_BYPID, pid, sizeof(struct kinfo_file), 0 };
	size_t len = 0;

	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		return NULL;
	}
	len += sizeof(struct kinfo_file) * 8;
	struct kinfo_file *kf = malloc(len);
	if (!kf) {
		return NULL;
	}
	mib[5] = (int)(len / sizeof(struct kinfo_file));
	if (sysctl(mib, 6, kf, &len, NULL, 0) == -1) {
		free(kf);
		return NULL;
	}

	RzList *ret = rz_list_newf((RzListFree)rz_debug_desc_free);
	if (!ret) {
		free(kf);
		return NULL;
	}

	size_t count = len / sizeof(struct kinfo_file);
	for (size_t i = 0; i < count; i++) {
		if (kf[i].ki_fd < 0) {
			continue;
		}
		int type = '-';
		switch (kf[i].ki_ftype) {
		case DTYPE_VNODE:
			type = 'v';
			break;
		case DTYPE_SOCKET:
			type = 's';
			break;
		case DTYPE_PIPE:
			type = 'p';
			break;
		case DTYPE_KQUEUE:
			type = 'k';
			break;
		default:
			type = '-';
			break;
		}
		int perm = 0;
		if (kf[i].ki_flag & FREAD) {
			perm |= RZ_PERM_R;
		}
		if (kf[i].ki_flag & FWRITE) {
			perm |= RZ_PERM_W;
		}
		char empty_path[] = "";
		RzDebugDesc *desc = rz_debug_desc_new(kf[i].ki_fd, empty_path, perm, type, kf[i].ki_foffset);
		if (!desc) {
			break;
		}
		rz_list_append(ret, desc);
	}

	free(kf);
	return ret;
}

RZ_OWN RzList /*<RzDebugDesc *>*/ *bsd_desc_list(int pid) {
	RzList *ret = NULL;
	char path[512], file[512], buf[512];
	struct dirent *de;
	RzDebugDesc *desc;
	int type, perm;
	size_t len, len2;
	struct stat st;
	DIR *dd = NULL;

	rz_strf(path, "/proc/%i/fd/", pid);
	if (!(dd = opendir(path))) {
		return netbsd_sysctl_desc_list(pid);
	}
	ret = rz_list_newf((RzListFree)rz_debug_desc_free);
	if (!ret) {
		closedir(dd);
		return NULL;
	}
	while ((de = readdir(dd))) {
		if (de->d_name[0] == '.') {
			continue;
		}
		len = strlen(path);
		len2 = strlen(de->d_name);
		if (len + len2 + 1 >= sizeof(file)) {
			RZ_LOG_ERROR("Filename is too long.\n");
			goto fail;
		}
		memcpy(file, path, len);
		memcpy(file + len, de->d_name, len2 + 1);
		buf[0] = 0;
		ssize_t rlen = readlink(file, buf, sizeof(buf) - 1);
		if (rlen == -1) {
			RZ_LOG_ERROR("readlink %s failed.\n", file);
			goto fail;
		}
		buf[rlen] = '\0';
		type = perm = 0;
		if (stat(file, &st) != -1) {
			type = st.st_mode & S_IFIFO ? 'P' : st.st_mode & S_IFSOCK ? 'S'
				: st.st_mode & S_IFCHR                            ? 'C'
										  : '-';
		}
		if (lstat(file, &st) != -1) {
			if (st.st_mode & S_IRUSR) {
				perm |= RZ_PERM_R;
			}
			if (st.st_mode & S_IWUSR) {
				perm |= RZ_PERM_W;
			}
		}
		desc = rz_debug_desc_new(atoi(de->d_name), buf, perm, type, 0);
		if (!desc) {
			break;
		}
		rz_list_append(ret, desc);
	}
	closedir(dd);
	return ret;

fail:
	rz_list_free(ret);
	closedir(dd);
	return NULL;
}

static int get_rz_status(int stat) {
	switch (stat) {
	case LSRUN:
	case LSONPROC:
	case LSIDL:
		return RZ_DBG_PROC_RUN;
	case LSSTOP:
	case LSSUSPENDED:
		return RZ_DBG_PROC_STOP;
	case LSZOMB:
		return RZ_DBG_PROC_ZOMBIE;
	case LSSLEEP:
		return RZ_DBG_PROC_SLEEP;
	default:
		return RZ_DBG_PROC_DEAD;
	}
}

RZ_OWN RzList /*<RzDebugPid *>*/ *bsd_thread_list(RZ_NONNULL RzDebug *dbg, int pid, RZ_NONNULL RzList /*<RzDebugPid *>*/ *list) {
	rz_return_val_if_fail(dbg && list, NULL);
	char errbuf[_POSIX2_LINE_MAX];
	int cnt = 0, np = 0;

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
	if (!kd) {
		RZ_LOG_ERROR("kvm_openfiles failed: %s\n", errbuf);
		rz_list_free(list);
		return NULL;
	}

	struct kinfo_proc2 *kp = kvm_getproc2(kd, KERN_PROC_PID, pid, sizeof(*kp), &np);
	uid_t uid = (kp && np > 0) ? kp->p_uid : 0;
	const char *comm = (kp && np > 0) ? kp->p_comm : "";

	struct kinfo_lwp *kl = kvm_getlwps(kd, pid, 0, sizeof(struct kinfo_lwp), &cnt);
	if (!kl) {
		kvm_close(kd);
		rz_list_free(list);
		return NULL;
	}

	for (int i = 0; i < cnt; i++) {
		int lwp_stat = get_rz_status(kl[i].l_stat);
		const char *th_name = kl[i].l_name[0] ? kl[i].l_name : comm;
		RzDebugPid *pid_info = rz_debug_pid_new(th_name, kl[i].l_lid,
			uid, lwp_stat, (ut64)kl[i].l_wchan);
		if (pid_info) {
			rz_list_append(list, pid_info);
		}
	}

	kvm_close(kd);
	return list;
}

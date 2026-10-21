// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <signal.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <kvm.h>
#include <limits.h>
#include <rz_util/rz_log.h>
#include "bsd_debug.h"

int bsd_handle_signals(RZ_NONNULL RzDebug *dbg) {
	rz_return_val_if_fail(dbg, -1);
	ptrace_state_t state = { 0 };
	if (ptrace(PT_GET_PROCESS_STATE, dbg->pid, (caddr_t)&state, sizeof(state)) == -1) {
		if (errno == ESRCH) {
			dbg->reason.type = RZ_DEBUG_REASON_DEAD;
			return 0;
		}
		rz_sys_perror("ptrace PT_GET_PROCESS_STATE");
		return -1;
	}

	if (state.pe_tid > 0) {
		dbg->reason.tid = state.pe_tid;
	}

	switch (state.pe_report_event) {
	case PTRACE_FORK:
	case PTRACE_VFORK:
		dbg->forked_pid = state.pe_other_pid;
		dbg->reason.type = RZ_DEBUG_REASON_NEW_PID;
		return 0;
#ifdef PTRACE_LWP_CREATE
	case PTRACE_LWP_CREATE:
		dbg->reason.type = RZ_DEBUG_REASON_NEW_TID;
		return 0;
#endif
#ifdef PTRACE_LWP_EXIT
	case PTRACE_LWP_EXIT:
		dbg->reason.type = RZ_DEBUG_REASON_EXIT_TID;
		return 0;
#endif
	default:
		break;
	}

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
	struct kinfo_proc *kp;
	char err[_POSIX2_LINE_MAX];
	int rc = 0;
	RzDebugInfo *rdi = RZ_NEW0(RzDebugInfo);
	if (!rdi) {
		return NULL;
	}

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, err);
	if (!kd) {
		free(rdi);
		return NULL;
	}

	kp = kvm_getprocs(kd, KERN_PROC_PID, dbg->pid, sizeof(*kp), &rc);
	if (kp && rc > 0) {
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
		case SSLEEP:
			rdi->status = RZ_DBG_PROC_SLEEP;
			break;
		default:
			rdi->status = RZ_DBG_PROC_RUN;
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

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
	if (!kd) {
		RZ_LOG_ERROR("kvm_openfiles failed: %s\n", errbuf);
		rz_list_free(list);
		return NULL;
	}

	kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc), &cnt);
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
	struct kinfo_vmentry entry = { 0 };
	size_t len = sizeof(entry);
	int mib[3] = { CTL_KERN, KERN_PROC_VMMAP, dbg->pid };
	u_long old_end = 0;

	if (sysctl(mib, 3, &entry, &len, NULL, 0) == -1) {
		RZ_LOG_ERROR("Could not get memory map: %s\n", strerror(errno));
		return NULL;
	}

	RzList *list = rz_debug_map_list_new();
	if (!list) {
		return NULL;
	}

	while (sysctl(mib, 3, &entry, &len, NULL, 0) != -1) {
		if (old_end == entry.kve_end) {
			/* No more entries */
			break;
		}
		int perm = 0;
		if (entry.kve_protection & KVE_PROT_READ) {
			perm |= RZ_PERM_R;
		}
		if (entry.kve_protection & KVE_PROT_WRITE) {
			perm |= RZ_PERM_W;
		}
		if (entry.kve_protection & KVE_PROT_EXEC) {
			perm |= RZ_PERM_X;
		}

		char empty_name[] = "";
		RzDebugMap *map = rz_debug_map_new(empty_name, entry.kve_start, entry.kve_end, perm, 0);
		if (!map) {
			break;
		}
		map->offset = entry.kve_offset;
		rz_list_append(list, map);

		entry.kve_start = entry.kve_start + 1;
		old_end = entry.kve_end;
	}

	return list;
}

RZ_OWN RzList /*<RzDebugDesc *>*/ *bsd_desc_list(int pid) {
	char errbuf[_POSIX2_LINE_MAX];
	int cnt = 0;

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
	if (!kd) {
		RZ_LOG_ERROR("kvm_openfiles failed: %s\n", errbuf);
		return NULL;
	}

	struct kinfo_file *kf = kvm_getfiles(kd, KERN_FILE_BYPID, pid, sizeof(struct kinfo_file), &cnt);
	if (!kf) {
		kvm_close(kd);
		return NULL;
	}

	RzList *ret = rz_list_newf((RzListFree)rz_debug_desc_free);
	if (!ret) {
		kvm_close(kd);
		return NULL;
	}

	for (int i = 0; i < cnt; i++) {
		if (kf[i].fd_fd < 0) {
			continue;
		}
		int type = '-';
		char path[512];
		path[0] = '\0';

		switch (kf[i].f_type) {
		case DTYPE_VNODE:
			type = 'v';
			rz_str_ncpy(path, kf[i].f_mntonname, sizeof(path));
			break;
		case DTYPE_SOCKET:
			type = 's';
			if (kf[i].so_family == AF_UNIX) {
				rz_str_ncpy(path, kf[i].unp_path, sizeof(path));
			} else if (kf[i].so_family == AF_INET) {
				char laddr[INET_ADDRSTRLEN] = { 0 };
				char faddr[INET_ADDRSTRLEN] = { 0 };
				struct in_addr in_l = { .s_addr = kf[i].inp_laddru[0] };
				struct in_addr in_f = { .s_addr = kf[i].inp_faddru[0] };
				inet_ntop(AF_INET, &in_l, laddr, sizeof(laddr));
				inet_ntop(AF_INET, &in_f, faddr, sizeof(faddr));
				snprintf(path, sizeof(path), "%s:%u %s:%u",
					laddr, ntohs((uint16_t)kf[i].inp_lport),
					faddr, ntohs((uint16_t)kf[i].inp_fport));
			} else if (kf[i].so_family == AF_INET6) {
				char laddr[INET6_ADDRSTRLEN] = { 0 };
				char faddr[INET6_ADDRSTRLEN] = { 0 };
				inet_ntop(AF_INET6, kf[i].inp_laddru, laddr, sizeof(laddr));
				inet_ntop(AF_INET6, kf[i].inp_faddru, faddr, sizeof(faddr));
				snprintf(path, sizeof(path), "[%s]:%u [%s]:%u",
					laddr, ntohs((uint16_t)kf[i].inp_lport),
					faddr, ntohs((uint16_t)kf[i].inp_fport));
			}
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
		if (kf[i].f_flag & FREAD) {
			perm |= RZ_PERM_R;
		}
		if (kf[i].f_flag & FWRITE) {
			perm |= RZ_PERM_W;
		}

		RzDebugDesc *desc = rz_debug_desc_new(kf[i].fd_fd, path, perm, type, kf[i].f_offset);
		if (!desc) {
			break;
		}
		rz_list_append(ret, desc);
	}

	kvm_close(kd);
	return ret;
}

static int get_rz_status(int stat) {
	switch (stat) {
	case SRUN:
	case SIDL:
	case SONPROC:
		return RZ_DBG_PROC_RUN;
	case SSTOP:
		return RZ_DBG_PROC_STOP;
	case SZOMB:
		return RZ_DBG_PROC_ZOMBIE;
	case SSLEEP:
		return RZ_DBG_PROC_SLEEP;
	default:
		return RZ_DBG_PROC_DEAD;
	}
}

RZ_OWN RzList /*<RzDebugPid *>*/ *bsd_thread_list(RZ_NONNULL RzDebug *dbg, int pid, RZ_NONNULL RzList /*<RzDebugPid *>*/ *list) {
	rz_return_val_if_fail(dbg && list, NULL);
	char errbuf[_POSIX2_LINE_MAX];
	int cnt = 0;

	kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
	if (!kd) {
		RZ_LOG_ERROR("kvm_openfiles failed: %s\n", errbuf);
		rz_list_free(list);
		return NULL;
	}

	struct kinfo_proc *kp = kvm_getprocs(kd, KERN_PROC_PID | KERN_PROC_SHOW_THREADS,
		pid, sizeof(*kp), &cnt);
	if (!kp) {
		kvm_close(kd);
		rz_list_free(list);
		return NULL;
	}

	for (int i = 0; i < cnt; i++) {
		if (kp[i].p_tid == -1) {
			continue;
		}
		int pid_stat = get_rz_status(kp[i].p_stat);
		RzDebugPid *pid_info = rz_debug_pid_new(kp[i].p_comm, kp[i].p_tid,
			kp[i].p_uid, pid_stat, (ut64)kp[i].p_wchan);
		if (pid_info) {
			rz_list_append(list, pid_info);
		}
	}

	kvm_close(kd);
	return list;
}

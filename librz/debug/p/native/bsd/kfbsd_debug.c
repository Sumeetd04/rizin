// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <kvm.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <libutil.h>
#include <rz_util/rz_log.h>
#include "bsd_debug.h"

static void addr_to_string(struct sockaddr_storage *ss, char *buffer, int buflen) {
	char buffer2[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;

	if (buflen <= 0) {
		return;
	}
	switch (ss->ss_family) {
	case AF_LOCAL:
		sun = (struct sockaddr_un *)ss;
		strncpy(buffer, (sun && *sun->sun_path) ? sun->sun_path : "-", buflen - 1);
		buffer[buflen - 1] = '\0';
		break;
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		snprintf(buffer, buflen, "%s:%d", inet_ntoa(sin->sin_addr),
			ntohs(sin->sin_port));
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		if (inet_ntop(AF_INET6, &sin6->sin6_addr, buffer2,
			    sizeof(buffer2)) != NULL) {
			snprintf(buffer, buflen, "%s.%d", buffer2,
				ntohs(sin6->sin6_port));
		} else {
			rz_str_ncpy(buffer, "-", buflen);
		}
		break;
	default:
		*buffer = 0;
		break;
	}
}

int bsd_handle_signals(RZ_NONNULL RzDebug *dbg) {
	rz_return_val_if_fail(dbg, -1);
	struct ptrace_lwpinfo linfo = { 0 };
	int ret = ptrace(PT_LWPINFO, dbg->pid, (caddr_t)&linfo, sizeof(linfo));
	if (ret == -1) {
		if (errno == ESRCH) {
			dbg->reason.type = RZ_DEBUG_REASON_DEAD;
			return 0;
		}
		rz_sys_perror("ptrace PTRACE_LWPINFO");
		return -1;
	}

	siginfo_t siginfo = linfo.pl_siginfo;
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
	rz_return_val_if_fail(dbg && path, false);
	(void)path;
#ifdef PT_COREDUMP
	if (!dest) {
		return false;
	}
	struct ptrace_coredump pc = { .pc_fd = dest->fd, .pc_flags = PC_ALL, .pc_limit = 0 };
	return ptrace(PT_COREDUMP, dbg->pid, (caddr_t)&pc, sizeof(pc)) != -1;
#else
	(void)dest;
	return false;
#endif
}

RZ_OWN RzDebugInfo *bsd_info(RZ_NONNULL RzDebug *dbg, RZ_NULLABLE const char *arg) {
	rz_return_val_if_fail(dbg, NULL);
	(void)arg;
	struct kinfo_proc *kp;
	RzDebugInfo *rdi = RZ_NEW0(RzDebugInfo);
	if (!rdi) {
		return NULL;
	}

	if (!(kp = kinfo_getproc(dbg->pid))) {
		free(rdi);
		return NULL;
	}

	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = kp->ki_uid;
	rdi->gid = kp->ki_pgid;
	rdi->exe = rz_str_dup(kp->ki_comm);

	switch (kp->ki_stat) {
	case SSLEEP:
		rdi->status = RZ_DBG_PROC_SLEEP;
		break;
	case SSTOP:
		rdi->status = RZ_DBG_PROC_STOP;
		break;
	case SZOMB:
		rdi->status = RZ_DBG_PROC_ZOMBIE;
		break;
	case SRUN:
	case SIDL:
	case SLOCK:
	case SWAIT:
		rdi->status = RZ_DBG_PROC_RUN;
		break;
	default:
		rdi->status = RZ_DBG_PROC_DEAD;
		break;
	}

	free(kp);

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

	kp = kvm_getprocs(kd, KERN_PROC_PROC, 0, &cnt);
	for (int i = 0; i < cnt; i++) {
		entry = kp + i;
		// Unless pid 0 is requested, only add the requested pid and its child processes
		if (pid == 0 || entry->ki_pid == pid || entry->ki_ppid == pid) {
			RzDebugPid *p = rz_debug_pid_new(entry->ki_comm, entry->ki_pid, entry->ki_uid, 's', 0);
			if (p) {
				p->ppid = entry->ki_ppid;
				rz_list_append(list, p);
			}
		}
	}

	kvm_close(kd);
	return list;
}

RZ_OWN RzList /*<RzDebugMap *>*/ *bsd_native_sysctl_map(RZ_NONNULL RzDebug *dbg) {
	rz_return_val_if_fail(dbg, NULL);
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, dbg->pid };
	size_t len = 0;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
		return NULL;
	}
	len = len * 4 / 3;
	char *buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) {
		free(buf);
		return NULL;
	}
	char *bp = buf;
	char *eb = buf + len;
	RzList *list = rz_debug_map_list_new();
	if (!list) {
		free(buf);
		return NULL;
	}
	while (bp < eb) {
		struct kinfo_vmentry *kve = (struct kinfo_vmentry *)(void *)bp;
		int perm = 0;
		if (kve->kve_protection & KVME_PROT_READ) {
			perm |= RZ_PERM_R;
		}
		if (kve->kve_protection & KVME_PROT_WRITE) {
			perm |= RZ_PERM_W;
		}
		if (kve->kve_protection & KVME_PROT_EXEC) {
			perm |= RZ_PERM_X;
		}

		RzDebugMap *map = rz_debug_map_new(kve->kve_path, kve->kve_start, kve->kve_end, perm, 0);
		if (!map) {
			break;
		}
		map->offset = kve->kve_offset;
		map->file = rz_str_dup(kve->kve_path);
		rz_list_append(list, map);

		bp += kve->kve_structsize;
	}
	free(buf);
	return list;
}

RZ_OWN RzList /*<RzDebugDesc *>*/ *bsd_desc_list(int pid) {
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid };
	size_t len = 0;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
		return NULL;
	}
	len = len * 4 / 3;
	char *buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) {
		free(buf);
		return NULL;
	}
	char *bp = buf;
	char *eb = buf + len;
	RzList *ret = rz_list_newf((RzListFree)rz_debug_desc_free);
	if (!ret) {
		free(buf);
		return NULL;
	}
	while (bp < eb) {
		struct kinfo_file *kf = (struct kinfo_file *)(void *)bp;
		bp += kf->kf_structsize;
		if (kf->kf_fd < 0) {
			continue; // Skip root and cwd. We need it ??
		}
		int perm = 0;
		int type = 0;
		char *path = kf->kf_path;
		char str[sizeof(kf->kf_path)];
		str[0] = 0;
		switch (kf->kf_type) {
		case KF_TYPE_VNODE:
			type = 'v';
			break;
		case KF_TYPE_SOCKET:
			type = 's';
			if (kf->kf_sock_domain == AF_LOCAL) {
				struct sockaddr_un *un = (struct sockaddr_un *)&kf->kf_sa_local;
				if (un->sun_path[0] != 0) {
					addr_to_string(&kf->kf_sa_local, str, sizeof(str));
				} else {
					addr_to_string(&kf->kf_sa_peer, str, sizeof(str));
				}
			} else {
				addr_to_string(&kf->kf_sa_local, str, sizeof(str));
				rz_str_ncat(str, " ", sizeof(str));
				addr_to_string(&kf->kf_sa_peer, str + strlen(str), sizeof(str) - strlen(str));
			}
			path = str;
			break;
		case KF_TYPE_PIPE:
			type = 'p';
			break;
		case KF_TYPE_FIFO:
			type = 'f';
			break;
		case KF_TYPE_KQUEUE:
			type = 'k';
			break;
		case KF_TYPE_MQUEUE:
			type = 'm';
			break;
		case KF_TYPE_SHM:
			type = 'h';
			break;
		case KF_TYPE_PTS:
			type = 't';
			break;
		case KF_TYPE_SEM:
			type = 'e';
			break;
		case KF_TYPE_NONE:
		case KF_TYPE_PROC:
		case KF_TYPE_UNKNOWN:
		default:
			type = '-';
			break;
		}
		perm = (kf->kf_flags & KF_FLAG_READ) ? RZ_PERM_R : 0;
		perm |= (kf->kf_flags & KF_FLAG_WRITE) ? RZ_PERM_W : 0;
		RzDebugDesc *desc = rz_debug_desc_new(kf->kf_fd, path, perm, type, kf->kf_offset);
		if (!desc) {
			break;
		}
		rz_list_append(ret, desc);
	}

	free(buf);
	return ret;
}

static int get_rz_status(int stat) {
	switch (stat) {
	case SRUN:
	case SIDL:
	case SLOCK:
	case SWAIT:
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
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID | KERN_PROC_INC_THREAD, pid };
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
		int pid_stat = get_rz_status(kp[i].ki_stat);
		RzDebugPid *pid_info = rz_debug_pid_new(kp[i].ki_comm, kp[i].ki_tid,
			kp[i].ki_uid, pid_stat, (ut64)(size_t)kp[i].ki_wchan);
		if (pid_info) {
			rz_list_append(list, pid_info);
		}
	}

	free(kp);
	return list;
}

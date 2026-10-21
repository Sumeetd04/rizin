// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_drx.h>
#include <errno.h>
#include <sys/wait.h>
#include <signal.h>

#include "bsd/bsd_debug.h"
#include "procfs.h"
#include "drx.c"
#include "bt.c"

#ifdef __WALL
#define WAITPID_FLAGS __WALL
#else
#define WAITPID_FLAGS 0
#endif

#define PROC_NAME_SZ   1024
#define PROC_REGION_SZ 100
// PROC_REGION_SZ - 2 (used for `0x`). Due to how RZ_STR_DEF works this can't be
// computed.
#define PROC_REGION_LEFT_SZ 98
#define PROC_PERM_SZ        5
#define PROC_UNKSTR_SZ      128

static int rz_debug_handle_signals(RzDebug *dbg) {
	return bsd_handle_signals(dbg);
}

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
#if __x86_64__ || __amd64__
#include "reg/openbsd-x64.h"
#endif
}

static bool rz_debug_native_step(RzDebug *dbg) {
	int ret = ptrace(PT_STEP, dbg->pid, (caddr_t)1, 0);
	if (ret != 0) {
		rz_sys_perror("native-singlestep");
		return false;
	}
	return true;
}

static int match_pid(const void *pid_o, const void *th_o, void *user) {
	int pid = *(int *)pid_o;
	RzDebugPid *th = (RzDebugPid *)th_o;
	return pid != th->pid;
}

static RZ_OWN RzList /*<RzDebugPid *>*/ *get_pid_thread_list(RZ_NONNULL RzDebug *dbg, int main_pid) {
	rz_return_val_if_fail(dbg, NULL);
	RzList *list = rz_list_new();
	if (!list) {
		RZ_LOG_ERROR("Cannot create thread list\n");
		return NULL;
	}
	list = bsd_thread_list(dbg, main_pid, list);
	dbg->main_pid = main_pid;
	return list;
}

static int rz_debug_native_attach(RzDebug *dbg, int pid) {
	if (!dbg->threads) {
		dbg->threads = get_pid_thread_list(dbg, pid);
		return pid;
	}
	if (!rz_list_find(dbg->threads, &pid, &match_pid, NULL)) {
		int ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
		if (ret == -1) {
			RZ_LOG_ERROR("Trying to attach to %d\n", pid);
			rz_sys_perror("ptrace (PT_ATTACH)");
		}
	}
	return pid;
}

static int rz_debug_native_detach(RzDebug *dbg, int pid) {
	return ptrace(PT_DETACH, pid, NULL, 0);
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int num) {
	ut64 pc = rz_debug_reg_get(dbg, "PC");
	errno = 0;
	return ptrace(PTRACE_SYSCALL, pid, (void *)(size_t)pc, 0) == 0;
}

static int rz_debug_native_stop(RzDebug *dbg) {
	return 0;
}

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
	void *data = (void *)(size_t)((sig != -1) ? sig : dbg->reason.signum);
	ut64 pc = rz_debug_reg_get(dbg, "PC");
	return ptrace(PTRACE_CONT, pid, (void *)(size_t)pc, (int)(size_t)data) == 0;
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	return bsd_info(dbg, arg);
}

static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		RZ_LOG_ERROR("rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}
	int status = -1;
	int ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		rz_sys_perror("waitpid");
		return RZ_DEBUG_REASON_ERROR;
	}

	RZ_LOG_DEBUG("rz_debug_native_wait: status=%d (0x%x) (return=%d)\n", status, status, ret);
	dbg->reason.tid = pid;
	if (reason == RZ_DEBUG_REASON_ERROR) {
		return reason;
	}
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		if (WIFEXITED(status)) {
			if (dbg->pid == pid) {
				RZ_LOG_WARN("(%" PFMT32d ") Process exited with status=0x%x\n", pid, WEXITSTATUS(status));
			} else {
				RZ_LOG_WARN("(%" PFMT32d ") Thread exited with status=0x%x\n", pid, WEXITSTATUS(status));
			}
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (WIFSIGNALED(status)) {
			RZ_LOG_WARN("child received signal %d\n", WTERMSIG(status));
			reason = RZ_DEBUG_REASON_SIGNAL;
		} else if (WIFSTOPPED(status)) {
			dbg->reason.signum = WSTOPSIG(status);
			if (rz_debug_handle_signals(dbg) != 0) {
				return RZ_DEBUG_REASON_ERROR;
			}
			reason = dbg->reason.type;
#ifdef WIFCONTINUED
		} else if (WIFCONTINUED(status)) {
			RZ_LOG_WARN("child continued...\n");
			reason = RZ_DEBUG_REASON_NONE;
#endif
		} else if (status == 1) {
			RZ_LOG_WARN("debugger is dead with status 1!\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (status == 0) {
			RZ_LOG_WARN("debugger is dead with status 0\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else {
			if (ret != pid) {
				reason = RZ_DEBUG_REASON_NEW_PID;
			} else {
				RZ_LOG_ERROR("returning from wait without knowing why...\n");
			}
		}
	}
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		RZ_LOG_ERROR("%s: Unable to find why the process stopped.\n", __func__);
		reason = RZ_DEBUG_REASON_ERROR;
	}
	dbg->reason.type = reason;
	return reason;
}

#undef MAXPID
#define MAXPID 99999

static RzList /*<RzDebugPid *>*/ *rz_debug_native_pids(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	return bsd_pid_list(dbg, pid, list);
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		RZ_LOG_ERROR("Cannot create list\n");
		return NULL;
	}
	return bsd_thread_list(dbg, pid, list);
}

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	return 0;
}

static int bsd_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	int pid = dbg->pid;
	int ret;
	if (type < -1) {
		type = -type;
	}
	switch (type) {
	case RZ_REG_TYPE_DRX:
		return true;
	case RZ_REG_TYPE_FPU:
	case RZ_REG_TYPE_MMX:
	case RZ_REG_TYPE_XMM: {
		struct fpreg fpregs;
		memset(&fpregs, 0, sizeof(fpregs));
		memset(buf, 0, size);
		ret = ptrace(PT_GETFPREGS, pid, (caddr_t)&fpregs, sizeof(fpregs));
		if (ret != 0) {
			return false;
		}
		if (sizeof(fpregs) < (size_t)size) {
			size = sizeof(fpregs);
		}
		memcpy(buf, &fpregs, size);
		return sizeof(fpregs);
	}
	case RZ_REG_TYPE_SEG:
	case RZ_REG_TYPE_FLG:
	case RZ_REG_TYPE_GPR: {
		RZ_DEBUG_REG_T regs;
		memset(&regs, 0, sizeof(regs));
		memset(buf, 0, size);
		ret = ptrace(PT_GETREGS, pid, (caddr_t)&regs, sizeof(regs));
		// if perror here says 'no such process' and the
		// process exists still.. is because there's a
		// missing call to 'wait'. and the process is not
		// yet available to accept more ptrace queries.
		if (ret != 0) {
			return false;
		}
		if (sizeof(regs) < (size_t)size) {
			size = sizeof(regs);
		}
		memcpy(buf, &regs, size);
		return sizeof(regs);
	}
	}
	return true;
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	return bsd_reg_read(dbg, type, buf, size);
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	// XXX use switch or so
	if (type == RZ_REG_TYPE_DRX) {
#if __i386__ || __x86_64__
		return bsd_reg_write(dbg, type, buf, size);
#else // i386/x86-64
		return false;
#endif
	} else if (type == RZ_REG_TYPE_GPR) {
		return bsd_reg_write(dbg, type, buf, size);
	} else if (type == RZ_REG_TYPE_FPU) {
		return bsd_reg_write(dbg, type, buf, size);
	} else {
		RZ_LOG_DEBUG("TODO: reg_write_non-gpr (%d)\n", type);
	}
	return false;
}

static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	// malloc not implemented for this platform
	return NULL;
}

static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	// mdealloc not implemented for this platform
	return false;
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_map_get(RzDebug *dbg) {
	if (dbg->pid == -1) {
		return NULL;
	}
	/* OpenBSD has no procfs; query memory maps via sysctl. */
	return bsd_native_sysctl_map(dbg);
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_modules_get(RzDebug *dbg) {
	char *lastname = NULL;
	RzDebugMap *map;
	RzListIter *iter, *iter2;
	RzList *list, *last;
	bool must_delete;
	if (!(list = rz_debug_native_map_get(dbg))) {
		return NULL;
	}
	if (!(last = rz_list_newf((RzListFree)rz_debug_map_free))) {
		rz_list_free(list);
		return NULL;
	}
	rz_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			file = map->file = rz_str_dup(map->name);
		}
		must_delete = true;
		if (file && *file == '/') {
			if (!lastname || strcmp(lastname, file)) {
				must_delete = false;
			}
		}
		if (must_delete) {
			rz_list_delete(list, iter);
		} else {
			rz_list_append(last, map);
			free(lastname);
			lastname = rz_str_dup(file);
		}
	}
	list->free = NULL;
	free(lastname);
	rz_list_free(list);
	return last;
}

static bool rz_debug_native_kill(RzDebug *dbg, int pid, int tid, int sig) {
	bool ret = false;
	if (pid == 0) {
		pid = dbg->pid;
	}
	if (sig == SIGKILL && dbg->threads) {
		rz_list_free(dbg->threads);
		dbg->threads = NULL;
	}
	if ((rz_sys_kill(pid, sig) != -1)) {
		ret = true;
	}
	if (errno == 1) {
		ret = -true; // EPERM
	}
	return ret;
}

#if __i386__ || __x86_64__
static void sync_drx_regs(RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		RZ_LOG_ERROR("drx: Unsupported number of registers for get_debug_regs\n");
		return;
	}

	// sync drx regs
#define R dbg->reg
	regs[0] = rz_reg_getv(R, "dr0");
	regs[1] = rz_reg_getv(R, "dr1");
	regs[2] = rz_reg_getv(R, "dr2");
	regs[3] = rz_reg_getv(R, "dr3");
	/*
	RESERVED
	regs[4] = rz_reg_getv (R, "dr4");
	regs[5] = rz_reg_getv (R, "dr5");
*/
	regs[6] = rz_reg_getv(R, "dr6");
	regs[7] = rz_reg_getv(R, "dr7");
}
#endif

#if __i386__ || __x86_64__
static void set_drx_regs(RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		RZ_LOG_ERROR("drx: Unsupported number of registers for get_debug_regs\n");
		return;
	}

#define R dbg->reg
	rz_reg_setv(R, "dr0", regs[0]);
	rz_reg_setv(R, "dr1", regs[1]);
	rz_reg_setv(R, "dr2", regs[2]);
	rz_reg_setv(R, "dr3", regs[3]);
	rz_reg_setv(R, "dr6", regs[6]);
	rz_reg_setv(R, "dr7", regs[7]);
}
#endif

static int rz_debug_native_drx(RzDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
#if __i386__ || __x86_64__
	int retval = false;
	drxt regs[NUM_DRX_REGISTERS] = { 0 };
	// sync drx regs
	sync_drx_regs(dbg, regs, NUM_DRX_REGISTERS);

	switch (api_type) {
	case DRX_API_LIST:
		drx_list(regs);
		retval = false;
		break;
	case DRX_API_GET_BP:
		/* get the index of the breakpoint at addr */
		retval = drx_get_at(regs, addr);
		break;
	case DRX_API_REMOVE_BP:
		/* remove hardware breakpoint */
		drx_set(regs, n, addr, -1, 0, 0);
		retval = true;
		break;
	case DRX_API_SET_BP:
		/* set hardware breakpoint */
		drx_set(regs, n, addr, sz, rwx, g);
		retval = true;
		break;
	default:
		/* this should not happen, someone misused the API */
		RZ_LOG_ERROR("drx: Unsupported api type in rz_debug_native_drx\n");
		retval = false;
	}

	set_drx_regs(dbg, regs, NUM_DRX_REGISTERS);

	return retval;
#else
	RZ_LOG_ERROR("drx: Unsupported platform\n");
#endif
	return -1;
}

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	if (b && b->hw) {
#if __i386__ || __x86_64__
		return set
			? drx_add((RzDebug *)bp->user, bp, b)
			: drx_del((RzDebug *)bp->user, bp, b);
#endif
	}
	return false;
}

static RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return bsd_desc_list(pid);
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	return false;
}

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	return bsd_generate_corefile(dbg, path, dest);
}

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native = {
	.open = rz_debug_desc_native_open,
	.list = rz_debug_desc_native_list,
};

static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return true;
}

static void rz_debug_native_fini(RzDebug *dbg, void *user) {
	if (!user) {
		return;
	}
	free(user);
}

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "x86",
	.canstep = 1, // XXX it's 1 on some platforms...
	.init = &rz_debug_native_init,
	.fini = &rz_debug_native_fini,
	.step = &rz_debug_native_step,
	.cont = &rz_debug_native_continue,
	.stop = &rz_debug_native_stop,
	.contsc = &rz_debug_native_continue_syscall,
	.attach = &rz_debug_native_attach,
	.detach = &rz_debug_native_detach,
	// TODO: add native select for other platforms?
	.pids = &rz_debug_native_pids,
	.threads = &rz_debug_native_threads,
	.wait = &rz_debug_native_wait,
	.kill = &rz_debug_native_kill,
	.frames = &rz_debug_native_frames, // rename to backtrace ?
	.reg_profile = rz_debug_native_reg_profile,
	.reg_read = rz_debug_native_reg_read,
	.info = rz_debug_native_info,
	.reg_write = (void *)&rz_debug_native_reg_write,
	.map_alloc = rz_debug_native_map_alloc,
	.map_dealloc = rz_debug_native_map_dealloc,
	.map_get = rz_debug_native_map_get,
	.modules_get = rz_debug_native_modules_get,
	.map_protect = rz_debug_native_map_protect,
	.breakpoint = rz_debug_native_bp,
	.drx = rz_debug_native_drx,
	.gcore = rz_debug_gcore,
};

// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _BSD_DEBUG_H
#define _BSD_DEBUG_H

#include <rz_debug.h>
#include <sys/ptrace.h>
#include <machine/reg.h>

#define RZ_DEBUG_REG_T struct reg

int bsd_handle_signals(RZ_NONNULL RzDebug *dbg);
int bsd_reg_write(RZ_NONNULL RzDebug *dbg, int type, RZ_NONNULL const ut8 *buf, int size);
bool bsd_generate_corefile(RZ_NONNULL RzDebug *dbg, RZ_NONNULL char *path, RZ_NULLABLE RzBuffer *dest);
RZ_OWN RzDebugInfo *bsd_info(RZ_NONNULL RzDebug *dbg, RZ_NULLABLE const char *arg);
RZ_OWN RzList /*<RzDebugPid *>*/ *bsd_pid_list(RZ_NONNULL RzDebug *dbg, int pid, RZ_NONNULL RzList /*<RzDebugPid *>*/ *list);
RZ_OWN RzList /*<RzDebugMap *>*/ *bsd_native_sysctl_map(RZ_NONNULL RzDebug *dbg);
RZ_OWN RzList /*<RzDebugDesc *>*/ *bsd_desc_list(int pid);
RZ_OWN RzList /*<RzDebugPid *>*/ *bsd_thread_list(RZ_NONNULL RzDebug *dbg, int pid, RZ_NONNULL RzList /*<RzDebugPid *>*/ *list);

#endif

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "api/linux/proctal.h"
#include "api/linux/watch.h"
#include "api/linux/address.h"
#include "api/x86/dr.h"

static int enable_breakpoint(struct proctal_linux *pl, pid_t tid)
{
	if (!proctal_linux_ptrace_set_x86_reg(pl, tid, PROCTAL_LINUX_PTRACE_X86_REG_DR0, (unsigned long long) pl->p.watch.addr)) {
		return 0;
	}

	unsigned long long dr7;

	if (!proctal_linux_ptrace_get_x86_reg(pl, tid, PROCTAL_LINUX_PTRACE_X86_REG_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_dr_set_len(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_LEN_1B);

	if (proctal_watch_execute(&pl->p)) {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_X);
	} else if (proctal_watch_read(&pl->p) && proctal_watch_write(&pl->p)) {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_RW);
	} else {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_W);
	}

	proctal_x86_dr_enable_l(&dr7, PROCTAL_X86_DR_0, 1);

	if (!proctal_linux_ptrace_set_x86_reg(pl, tid, PROCTAL_LINUX_PTRACE_X86_REG_DR7, dr7)) {
		return 0;
	}

	return 1;
}

static int disable_breakpoint(struct proctal_linux *pl, pid_t tid)
{
	unsigned long long dr7;

	if (!proctal_linux_ptrace_get_x86_reg(pl, tid, PROCTAL_LINUX_PTRACE_X86_REG_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_dr_enable_l(&dr7, PROCTAL_X86_DR_0, 0);

	if (!proctal_linux_ptrace_set_x86_reg(pl, tid, PROCTAL_LINUX_PTRACE_X86_REG_DR7, dr7)) {
		return 0;
	}

	return 1;
}

int proctal_linux_watch_start(struct proctal_linux *pl)
{
	if (pl->p.watch.read && !pl->p.watch.write && !pl->p.watch.execute) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ);
		return 0;
	}

	if (pl->p.watch.read && !pl->p.watch.write && pl->p.watch.execute) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_EXECUTE);
		return 0;
	}

	if (!pl->p.watch.read && pl->p.watch.write && pl->p.watch.execute) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_WRITE_EXECUTE);
		return 0;
	}

	if (pl->p.watch.read && pl->p.watch.write && pl->p.watch.execute) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_WRITE_EXECUTE);
		return 0;
	}

	if (!proctal_linux_ptrace_attach(pl)) {
		return 0;
	}

	for (struct proctal_linux_ptrace_task *task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
		if (!enable_breakpoint(pl, task->tid)) {
			proctal_linux_ptrace_detach(pl);
			return 0;
		}
	}

	if (!proctal_linux_ptrace_cont(pl, 0)) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	return 1;
}

void proctal_linux_watch_stop(struct proctal_linux *pl)
{
	for (struct proctal_linux_ptrace_task *task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
		proctal_linux_ptrace_stop(pl, task->tid);
		disable_breakpoint(pl, task->tid);
	}

	proctal_linux_ptrace_detach(pl);
}

int proctal_linux_watch(struct proctal_linux *pl, void **addr)
{
	pid_t tid = proctal_linux_ptrace_catch_trap(pl, 0);

	if (tid == 0) {
		return 0;
	}

	proctal_linux_ptrace_get_instruction_address(pl, tid, addr);

	if (!proctal_linux_ptrace_cont(pl, tid)) {
		return 0;
	}

	return 1;
}

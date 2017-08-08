/*
 * Eventually this will need to be moved out of the watch module.
 */

#include "api/linux/proctal.h"
#include "api/linux/watch.h"
#include "api/linux/watch/implementation.h"
#include "api/x86_64/dr.h"

int proctal_linux_watch_implementation_breakpoint_enable(struct proctal_linux *pl, pid_t tid)
{
	if (pl->p.watch.read && !pl->p.watch.write && !pl->p.watch.execute) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ);
		return 0;
	}

	if (pl->p.watch.read && !pl->p.watch.write && pl->p.watch.execute) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_EXECUTE);
		return 0;
	}

	if (!pl->p.watch.read && pl->p.watch.write && pl->p.watch.execute) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_WRITE_EXECUTE);
		return 0;
	}

	if (pl->p.watch.read && pl->p.watch.write && pl->p.watch.execute) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_WRITE_EXECUTE);
		return 0;
	}

	if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR0, &pl->p.watch.addr)) {
		return 0;
	}

	unsigned long long dr7;

	if (!proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_64_dr_len_set(&dr7, PROCTAL_X86_64_DR_0, PROCTAL_X86_64_DR_LEN_1B);

	if (proctal_watch_execute(&pl->p)) {
		proctal_x86_64_dr_rw_set(&dr7, PROCTAL_X86_64_DR_0, PROCTAL_X86_64_DR_RW_X);
	} else if (proctal_watch_read(&pl->p) && proctal_watch_write(&pl->p)) {
		proctal_x86_64_dr_rw_set(&dr7, PROCTAL_X86_64_DR_0, PROCTAL_X86_64_DR_RW_RW);
	} else {
		proctal_x86_64_dr_rw_set(&dr7, PROCTAL_X86_64_DR_0, PROCTAL_X86_64_DR_RW_W);
	}

	proctal_x86_64_dr_l_set(&dr7, PROCTAL_X86_64_DR_0, 1);

	if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR7, &dr7)) {
		return 0;
	}

	return 1;
}

int proctal_linux_watch_implementation_breakpoint_disable(struct proctal_linux *pl, pid_t tid)
{
	unsigned long long dr7;

	if (!proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_64_dr_l_set(&dr7, PROCTAL_X86_64_DR_0, 0);

	if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR7, &dr7)) {
		return 0;
	}

	return 1;
}

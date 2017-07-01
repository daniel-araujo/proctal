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

static int check_errno_waitpid(struct proctal *p)
{
	if (errno == 0) {
		return 0;
	}

	switch (errno) {
	case EPERM:
		proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
		break;

	case ESRCH:
		proctal_set_error(p, PROCTAL_ERROR_PROCESS_NOT_FOUND);
		break;

	case EINTR:
		proctal_set_error(p, PROCTAL_ERROR_INTERRUPT);
		break;

	default:
		proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
		break;
	}

	return 1;
}

static int enable_breakpoint(struct proctal_linux *pl)
{
	if (!proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_DR0, (unsigned long long) pl->p.watch.addr)) {
		return 0;
	}

	unsigned long long dr7;

	if (!proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_DR7, &dr7)) {
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

	if (!proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_DR7, dr7)) {
		return 0;
	}

	return 1;
}

static int disable_breakpoint(struct proctal_linux *pl)
{
	unsigned long long dr7;

	if (!proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_dr_enable_l(&dr7, PROCTAL_X86_DR_0, 0);

	if (!proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_DR7, dr7)) {
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

	if (!enable_breakpoint(pl)) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	return 1;
}

void proctal_linux_watch_stop(struct proctal_linux *pl)
{
	// Assuming process is stopped.
	disable_breakpoint(pl);
	proctal_linux_ptrace_detach(pl);
}

int proctal_linux_watch(struct proctal_linux *pl, void **addr)
{
	if (!proctal_linux_ptrace_cont(pl)) {
		return 0;
	}

	int wstatus;

	for (;;) {
		int wresult = waitpid(pl->pid, &wstatus, WUNTRACED);

		if (wresult != pl->pid) {
			if (wresult == -1) {
				check_errno_waitpid(&pl->p);
				proctal_linux_ptrace_stop(pl);
				return 0;
			} else {
				// We're not interested in this signal.
				continue;
			}
		}

		if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
			proctal_set_error(&pl->p, PROCTAL_ERROR_PROCESS_EXITED);
			return 0;
		} else if (WIFSTOPPED(wstatus)) {
			int signal = WSTOPSIG(wstatus);

			switch (signal) {
			case SIGTRAP:
				proctal_linux_ptrace_get_instruction_address(pl, addr);

				return 1;

			case SIGINT:
			default:
				// Process sent signal to be stopped so we're letting go.
				kill(pl->pid, signal);

				proctal_set_error(&pl->p, PROCTAL_ERROR_PROCESS_EXITED);
				return 0;
			}

			break;
		}
	}
}

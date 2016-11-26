#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <linux/proctal.h>
#include <linux/watch.h>
#include <linux/addr.h>
#include <x86/dr.h>

static int enable_breakpoint(struct proctal_linux_watch *plw)
{
	if (!proctal_linux_ptrace_set_x86_reg(plw->pl, PROCTAL_LINUX_PTRACE_X86_REG_DR0, (unsigned long long) plw->pw.addr)) {
		return 0;
	}

	unsigned long long dr7;

	if (!proctal_linux_ptrace_get_x86_reg(plw->pl, PROCTAL_LINUX_PTRACE_X86_REG_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_dr_set_len(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_LEN_1B);

	if (proctal_watch_execute(&plw->pw)) {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_X);
	} else if (proctal_watch_read(&plw->pw) && proctal_watch_write(&plw->pw)) {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_RW);
	} else {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_W);
	}

	proctal_x86_dr_enable_l(&dr7, PROCTAL_X86_DR_0, 1);

	if (!proctal_linux_ptrace_set_x86_reg(plw->pl, PROCTAL_LINUX_PTRACE_X86_REG_DR7, dr7)) {
		return 0;
	}

	return 1;
}

static int disable_breakpoint(struct proctal_linux_watch *plw)
{
	unsigned long long dr7;

	if (!proctal_linux_ptrace_get_x86_reg(plw->pl, PROCTAL_LINUX_PTRACE_X86_REG_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_dr_enable_l(&dr7, PROCTAL_X86_DR_0, 0);

	if (!proctal_linux_ptrace_set_x86_reg(plw->pl, PROCTAL_LINUX_PTRACE_X86_REG_DR7, dr7)) {
		return 0;
	}

	return 1;
}

static int start(struct proctal_linux_watch *plw)
{
	if (plw->pw.read && !plw->pw.write && !plw->pw.execute) {
		proctal_set_error(&plw->pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ);
		return 0;
	}

	if (plw->pw.read && !plw->pw.write && plw->pw.execute) {
		proctal_set_error(&plw->pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_EXECUTE);
		return 0;
	}

	if (!plw->pw.read && plw->pw.write && plw->pw.execute) {
		proctal_set_error(&plw->pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_WRITE_EXECUTE);
		return 0;
	}

	if (plw->pw.read && plw->pw.write && plw->pw.execute) {
		proctal_set_error(&plw->pl->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_WRITE_EXECUTE);
		return 0;
	}

	if (!proctal_linux_ptrace_attach(plw->pl)) {
		return 0;
	}

	if (!enable_breakpoint(plw)) {
		proctal_linux_ptrace_detach(plw->pl);
		return 0;
	}

	if (!proctal_linux_ptrace_cont(plw->pl)) {
		disable_breakpoint(plw);
		return 0;
	}

	plw->pw.started = 1;

	return 1;
}

void proctal_linux_watch_init(struct proctal_linux *pl, struct proctal_linux_watch *plw)
{
	proctal_watch_init(&pl->p, &plw->pw);

	plw->pl = pl;
}

void proctal_linux_watch_deinit(struct proctal_linux *pl, struct proctal_linux_watch *plw)
{
	if (plw->pw.started) {
		proctal_linux_ptrace_stop(plw->pl);

		disable_breakpoint(plw);

		proctal_linux_ptrace_detach(plw->pl);
	}

	proctal_watch_deinit(&pl->p, &plw->pw);
}

int proctal_linux_watch_next(struct proctal_linux_watch *plw, void **addr)
{
	if (!plw->pw.started) {
		if (!start(plw)) {
			return 0;
		}
	}

	int wstatus;

	for (;;) {
		if (waitpid(plw->pl->pid, &wstatus, WUNTRACED) != plw->pl->pid) {
			// If it failed due to an interrupt, we're not going to
			// consider this an error.
			if (errno != EINTR) {
				proctal_set_error(&plw->pl->p, PROCTAL_ERROR_UNKNOWN);
			}

			return 0;
		}

		if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
			// Process is gone, nothing to do anymore.
			break;
		} else if (WIFSTOPPED(wstatus)) {
			int signal = WSTOPSIG(wstatus);

			switch (signal) {
			case SIGTRAP: {
				void *rip;

				proctal_linux_ptrace_get_instruction_address(plw->pl, &rip);

				*addr = rip;

				proctal_linux_ptrace_cont(plw->pl);

				break;
			}

			case SIGINT:
			default:
				// Process was signal to be stopped. We're letting go.
				kill(plw->pl->pid, signal);

				proctal_linux_ptrace_detach(plw->pl);

				return 0;
			}

			break;
		}
	}

	return 1;
}

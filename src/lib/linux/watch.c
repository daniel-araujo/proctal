#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <linux/proctal.h>
#include <linux/watch.h>
#include <linux/address.h>
#include <x86/dr.h>

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

static int start(struct proctal_linux *pl)
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

	if (!proctal_linux_ptrace_cont(pl)) {
		disable_breakpoint(pl);
		return 0;
	}

	return 1;
}

static void end(struct proctal_linux *pl)
{
	proctal_linux_ptrace_stop(pl);

	disable_breakpoint(pl);

	proctal_linux_ptrace_detach(pl);
}

int proctal_linux_watch(struct proctal_linux *pl, void **addr)
{
	if (!start(pl)) {
		return 0;
	}

	int wstatus;

	for (;;) {
		if (waitpid(pl->pid, &wstatus, WUNTRACED) != pl->pid) {
			// If it failed due to an interrupt, we're not going to
			// consider this an error.
			if (errno != EINTR) {
				proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
			}

			end(pl);
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

				proctal_linux_ptrace_get_instruction_address(pl, &rip);

				*addr = rip;

				proctal_linux_ptrace_cont(pl);

				break;
			}

			case SIGINT:
			default:
				// Process sent signal to be stopped. We're letting go.
				kill(pl->pid, signal);

				end(pl);
				return 0;
			}

			break;
		}
	}

	end(pl);
	return 1;
}

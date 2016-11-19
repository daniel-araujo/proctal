#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "internal.h"
#include "x86/dr.h"
#include "linux/ptrace.h"

struct proctal_watch {
	// Proctal instance.
	proctal p;

	// Address to watch.
	void *addr;

	// Whether it's attached to the process.
	// Also tells us when it has started.
	int started;

	// Whether to watch for reads.
	int read;

	// Whether to watch for writes.
	int write;

	// Whether to watch for instruction execution.
	int execute;
};

static int enable_breakpoint(proctal_watch pw)
{
	if (!proctal_linux_ptrace_set_x86_reg(pw->p, PROCTAL_LINUX_PTRACE_X86_REG_DR0, (unsigned long long) pw->addr)) {
		return 0;
	}

	unsigned long long dr7;

	if (!proctal_linux_ptrace_get_x86_reg(pw->p, PROCTAL_LINUX_PTRACE_X86_REG_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_dr_set_len(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_LEN_1B);

	if (proctal_watch_execute(pw)) {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_X);
	} else if (proctal_watch_read(pw) && proctal_watch_write(pw)) {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_RW);
	} else {
		proctal_x86_dr_set_rw(&dr7, PROCTAL_X86_DR_0, PROCTAL_X86_DR_RW_W);
	}

	proctal_x86_dr_enable_l(&dr7, PROCTAL_X86_DR_0, 1);

	if (!proctal_linux_ptrace_set_x86_reg(pw->p, PROCTAL_LINUX_PTRACE_X86_REG_DR7, dr7)) {
		return 0;
	}

	return 1;
}

static int disable_breakpoint(proctal_watch pw)
{
	unsigned long long dr7;

	if (!proctal_linux_ptrace_get_x86_reg(pw->p, PROCTAL_LINUX_PTRACE_X86_REG_DR7, &dr7)) {
		return 0;
	}

	proctal_x86_dr_enable_l(&dr7, PROCTAL_X86_DR_0, 0);

	if (!proctal_linux_ptrace_set_x86_reg(pw->p, PROCTAL_LINUX_PTRACE_X86_REG_DR7, dr7)) {
		return 0;
	}

	return 1;
}

static int start(proctal_watch pw)
{
	if (pw->read && !pw->write && !pw->execute) {
		proctal_set_error(pw->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ);
		return 0;
	}

	if (pw->read && !pw->write && pw->execute) {
		proctal_set_error(pw->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_EXECUTE);
		return 0;
	}

	if (!pw->read && pw->write && pw->execute) {
		proctal_set_error(pw->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_WRITE_EXECUTE);
		return 0;
	}

	if (pw->read && pw->write && pw->execute) {
		proctal_set_error(pw->p, PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_WRITE_EXECUTE);
		return 0;
	}

	if (!proctal_linux_ptrace_attach(pw->p)) {
		return 0;
	}

	if (!enable_breakpoint(pw)) {
		proctal_linux_ptrace_detach(pw->p);
		return 0;
	}

	if (!proctal_linux_ptrace_cont(pw->p)) {
		disable_breakpoint(pw);
		return 0;
	}

	pw->started = 1;

	return 1;
}

proctal_watch proctal_watch_create(proctal p)
{
	proctal_watch pw = proctal_alloc(p, sizeof *pw);

	if (pw == NULL) {
		proctal_set_error(p, PROCTAL_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	pw->p = p; 
	pw->addr = NULL;
	pw->started = 0;
	pw->read = 0;
	pw->write = 0;
	pw->execute = 0;

	return pw;
}

void proctal_watch_destroy(proctal_watch pw)
{
	if (pw == NULL) {
		return;
	}

	if (pw->started) {
		proctal_linux_ptrace_stop(pw->p);

		disable_breakpoint(pw);

		proctal_linux_ptrace_detach(pw->p);
	}

	proctal_dealloc(pw->p, pw);
}

void *proctal_watch_addr(proctal_watch pw)
{
	return pw->addr;
}

void proctal_watch_set_addr(proctal_watch pw, void *addr)
{
	pw->addr = addr;
}

int proctal_watch_read(proctal_watch pw)
{
	return pw->read;
}

void proctal_watch_set_read(proctal_watch pw, int r)
{
	pw->read = r != 0;
}

int proctal_watch_write(proctal_watch pw)
{
	return pw->write;
}

void proctal_watch_set_write(proctal_watch pw, int w)
{
	pw->write = w != 0;
}

int proctal_watch_execute(proctal_watch pw)
{
	return pw->execute;
}

void proctal_watch_set_execute(proctal_watch pw, int x)
{
	pw->execute = x != 0;
}

int proctal_watch_next(proctal_watch pw, void **addr)
{
	if (!pw->started) {
		if (!start(pw)) {
			return 0;
		}
	}

	int wstatus;

	for (;;) {
		if (waitpid(proctal_pid(pw->p), &wstatus, WUNTRACED) != proctal_pid(pw->p)) {
			// If it failed due to an interrupt, we're not going to
			// consider this an error.
			if (errno != EINTR) {
				proctal_set_error(pw->p, PROCTAL_ERROR_UNKNOWN);
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

				proctal_linux_ptrace_get_instruction_address(pw->p, &rip);

				*addr = rip;

				ptrace(PTRACE_CONT, proctal_pid(pw->p), 0, 0);

				break;
			}

			case SIGINT:
			default:
				// Process was signal to be stopped. We're letting go.
				kill(proctal_pid(pw->p), signal);

				proctal_linux_ptrace_detach(pw->p);

				return 0;
			}

			break;
		}
	}

	return 1;
}

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "proctal.h"
#include "internal.h"

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
};

#define DBG_REG_X86_DR0 0
#define DBG_REG_X86_DR1 1
#define DBG_REG_X86_DR2 2
#define DBG_REG_X86_DR3 3
#define DBG_REG_X86_DR4 4
#define DBG_REG_X86_DR5 5
#define DBG_REG_X86_DR6 6
#define DBG_REG_X86_DR7 7

static int get_instruction_address(proctal p, void **addr)
{
	size_t offset = offsetof(struct user, regs)
		+ offsetof(struct user_regs_struct, rip);

	errno = 0;

	*addr = (void *) ptrace(PTRACE_PEEKUSER, proctal_pid(p), offset, 0);

	if (errno) {
		return 0;
	}

	return 1;
}

static int get_debug_register(proctal p, int reg, long *val)
{
	size_t offset = offsetof(struct user, u_debugreg)
		+ sizeof (((struct user *) 0)->u_debugreg[0]) * reg;

	errno = 0;

	*val = ptrace(PTRACE_PEEKUSER, proctal_pid(p), offset, 0);

	if (errno) {
		return 0;
	}

	return 1;
}

static int set_debug_register(proctal p, int reg, long val)
{
	size_t offset = offsetof(struct user, u_debugreg)
		+ sizeof (((struct user *) 0)->u_debugreg[0]) * reg;

	errno = 0;

	ptrace(PTRACE_POKEUSER, proctal_pid(p), offset, val);

	if (errno) {
		return 0;
	}

	return 1;
}

static void wait_for_stop(proctal p)
{
	int wstatus;

	for (;;) {
		waitpid(proctal_pid(p), &wstatus, WUNTRACED);

		if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
			break;
		}
	}
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

	return pw;
}

void proctal_watch_destroy(proctal_watch pw)
{
	if (pw == NULL) {
		return;
	}

	if (pw->started) {
		proctal_ptrace_detach(pw->p);
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

int proctal_watch_next(proctal_watch pw, void **addr)
{
	if (!pw->started) {
		if (!proctal_ptrace_attach(pw->p)) {
			return 0;
		}

		pw->started = 1;

		wait_for_stop(pw->p);
	}

	if (!set_debug_register(pw->p, DBG_REG_X86_DR0, pw->addr)) {
		proctal_ptrace_detach(pw->p);
		return 0;
	}

	if (!set_debug_register(pw->p, DBG_REG_X86_DR7, 0x1 + (1 << 16))) {
		proctal_ptrace_detach(pw->p);
		return 0;
	}

	long dr7;

	if (!get_debug_register(pw->p, DBG_REG_X86_DR7, &dr7)) {
		proctal_ptrace_detach(pw->p);
		return 0;
	}

	int wstatus;

	ptrace(PTRACE_CONT, proctal_pid(pw->p), 0, 0);

	for (;;) {
		waitpid(proctal_pid(pw->p), &wstatus, WUNTRACED);

		if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
			// Process is gone, nothing to do anymore.
			break;
		} else if (WIFSTOPPED(wstatus)) {
			if (WSTOPSIG(wstatus) == SIGTRAP) {
				void *rip;
				get_instruction_address(pw->p, &rip);
				*addr = rip;
				if (!set_debug_register(pw->p, DBG_REG_X86_DR7, 0x0)) {
					proctal_ptrace_detach(pw->p);
					return 0;
				}
				break;
			}
		}
	}

	return 1;
}

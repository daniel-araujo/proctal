#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>

#include "proctal.h"
#include "internal.h"
#include "global.h"
#include "linux.h"

struct proctal {
	// Process ID. This identifies the process we're going to muck with.
	pid_t pid;

	// File handle to read from memory. Always seek before using.
	FILE *memr;

	// File handle to write to memory. Always seek before using.
	FILE *memw;

	void *(*malloc)(size_t);
	void (*free)(void *);

	// Last error.
	int error;

	// Whether we're attached to the process with ptrace.
	int ptrace;
};

proctal proctal_create(void)
{
	proctal p = proctal_global_malloc()(sizeof *p);

	if (p == NULL) {
		return p;
	}

	p->pid = 0;
	p->memr = NULL;
	p->memw = NULL;
	p->malloc = proctal_global_malloc();
	p->free = proctal_global_free();
	p->error = 0;
	p->ptrace = 0;

	return p;
}

void proctal_destroy(proctal p)
{
	if (p == NULL) {
		return;
	}

	if (p->memr) {
		fclose(p->memr);
	}

	if (p->memw) {
		fclose(p->memw);
	}

	proctal_global_free()(p);
}

void proctal_set_pid(proctal p, pid_t pid)
{
	if (p->memr) {
		fclose(p->memr);
		p->memr = NULL;
	}

	if (p->memw) {
		fclose(p->memw);
		p->memw = NULL;
	}

	p->pid = pid;
}

void proctal_set_malloc(proctal p, void *(*malloc)(size_t))
{
	p->malloc = malloc;
}

void proctal_set_free(proctal p, void (*free)(void *))
{
	p->free = free;
}

void proctal_set_error(proctal p, int error)
{
	p->error = error;
}

pid_t proctal_pid(proctal p)
{
	return p->pid;
}

int proctal_error(proctal p)
{
	if (p == NULL) {
		return PROCTAL_ERROR_OUT_OF_MEMORY;
	}

	return p->error;
}

void proctal_error_ack(proctal p)
{
	p->error = 0;
}

FILE *proctal_memr(proctal p)
{
	if (p->memr == NULL) {
		p->memr = fopen(proctal_linux_proc_path(p->pid, "mem"), "r");
	}

	return p->memr;
}

FILE *proctal_memw(proctal p)
{
	if (p->memw == NULL) {
		p->memw = fopen(proctal_linux_proc_path(p->pid, "mem"), "w");
	}

	return p->memw;
}

void *proctal_alloc(proctal p, size_t size)
{
	return p->malloc(size);
}

void proctal_dealloc(proctal p, void *addr)
{
	return p->free(addr);
}

int proctal_ptrace_attach(proctal p)
{
	if (p->ptrace) {
		--p->ptrace;

		return 1;
	}

	if (ptrace(PTRACE_ATTACH, proctal_pid(p), 0L, 0L) == -1) {
		switch (errno) {
		case EPERM:
			proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
			break;

		default:
			proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
			break;
		}

		return 0;
	}

	p->ptrace = 1;

	return 1;
}

int proctal_ptrace_detach(proctal p)
{
	if (p->ptrace) {
		if (--p->ptrace) {
			return 1;
		}
	}

	if (ptrace(PTRACE_DETACH, proctal_pid(p), 0L, 0L) == -1) {
		switch (errno) {
		case EACCES:
			proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
			break;

		default:
			proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
			break;
		}

		return 0;
	}

	p->ptrace = 0;

	return 1;
}

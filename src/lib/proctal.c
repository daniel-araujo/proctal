#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>

#include "internal.h"
#include "global.h"
#include "linux/proc.h"

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

pid_t proctal_pid(proctal p)
{
	return p->pid;
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

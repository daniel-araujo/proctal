#ifndef INTERNAL_H
#define INTERNAL_H

#include <stdio.h>

#include "proctal.h"

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

void proctal_set_error(proctal p, int error);

FILE *proctal_memr(proctal p);
FILE *proctal_memw(proctal p);

/*
 * Allocate and deallocate memory.
 */
void *proctal_alloc(proctal p, size_t size);
void proctal_dealloc(proctal p, void *addr);

#endif /* INTERNAL_H */

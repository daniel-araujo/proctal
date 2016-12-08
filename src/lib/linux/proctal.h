#ifndef LINUX_PROCTAL_H
#define LINUX_PROCTAL_H

#include <stdio.h>
#include <sys/types.h>

#include <proctal.h>
#include <linux/proc.h>

/*
 * Linux specific instance of Proctal.
 */
struct proctal_linux {
	// Base structure.
	struct proctal p;

	// Process ID. This identifies the process we're going to muck with.
	pid_t pid;

	// File handle for reading and writing to memory. Always seek before
	// using.
	FILE *mem;

	// Tracks how many times we've attached to the process with
	// ptrace. It's not attached if the value is 0.
	int ptrace;

	struct proctal_linux_address {
		int started;

		// Current address.
		void *curr;

		// Memory mappings of the address space.
		FILE *maps;

		// Current region being read.
		struct proctal_linux_mem_region region;
	} address;
};

/*
 * Initializes a Linux specific instance of Proctal.
 */
void proctal_linux_init(struct proctal_linux *pl);

/*
 * Deinitializes a Linux specific instance of Proctal.
 */
void proctal_linux_deinit(struct proctal_linux *pl);

/*
 * Sets the PID.
 */
void proctal_linux_set_pid(struct proctal_linux *pl, pid_t pid);

/*
 * Gets the PID.
 */
pid_t proctal_linux_pid(struct proctal_linux *pl);

#endif /* LINUX_PROCTAL_H */

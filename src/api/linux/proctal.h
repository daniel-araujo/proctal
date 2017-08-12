#ifndef API_LINUX_PROCTAL_H
#define API_LINUX_PROCTAL_H

#include <stdio.h>
#include <sys/types.h>
#include <darr.h>
#include <acur.h>

#include "api/proctal.h"
#include "api/linux/proc.h"

/*
 * A task managed by ptrace calls.
 */
struct proctal_linux_ptrace_task {
	pid_t tid;
	int running;
};

/*
 * Linux specific handle.
 */
struct proctal_linux {
	// Base structure.
	struct proctal p;

	// Process ID. This identifies the program we're going to muck with.
	pid_t pid;

	// File handle for reading and writing to memory. Always seek before
	// using.
	FILE *mem;

	struct proctal_linux_ptrace {
		// Tracks how many times we've attached to the process with
		// ptrace. It's not attached if the value is 0.
		int count;

		// Tasks tracked by ptrace. An array of
		// struct proctal_linux_ptrace_task.
		struct darr tasks;

		// A cursor on the whole tasks array.
		struct acur tasks_cursor;

		// A cursor on a single task.
		struct acur task_cursor;
	} ptrace;

	struct proctal_linux_address {
		int started;

		// Next address ready to be retrieved.
		void *current_address;

		// Current region.
		struct proctal_linux_proc_maps_region *current_region;

		// Memory mappings of the address space.
		struct proctal_linux_proc_maps maps;

		// Structure used to check if a region meets the requirements.
		struct proctal_linux_proc_maps_region_check region_check;
	} address;

	struct proctal_linux_region {
		int started;

		// Memory mappings of the address space.
		struct proctal_linux_proc_maps maps;

		// Structure used to check if a region meets the requirements.
		struct proctal_linux_proc_maps_region_check check;
	} region;
};

/*
 * Initializes a Linux specific handle.
 */
void proctal_linux_init(struct proctal_linux *pl);

/*
 * Deinitializes a Linux specific handle.
 */
void proctal_linux_deinit(struct proctal_linux *pl);

/*
 * Sets the PID.
 */
void proctal_linux_pid_set(struct proctal_linux *pl, pid_t pid);

/*
 * Gets the PID.
 */
pid_t proctal_linux_pid(struct proctal_linux *pl);

#endif /* API_LINUX_PROCTAL_H */

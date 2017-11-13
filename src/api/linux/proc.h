#ifndef API_LINUX_PROC_H
#define API_LINUX_PROC_H

#include <stdio.h>
#include <sys/types.h>

#include "api/darr/darr.h"

/*
 * An entry in the maps file.
 */
struct proctal_linux_proc_maps_region {
	// Start address.
	void *start;

	// End address.
	void *end;

	// Whether it's readable.
	int read;

	// Whether it's writable.
	int write;

	// Whether it's executable.
	int execute;

	// Name of the region. Ends with a NUL character. Will be empty if the
	// region has no name.
	struct proctal_darr name;
};

/*
 * An open maps file.
 */
struct proctal_linux_proc_maps {
	// A FILE pointer to the maps file.
	FILE *file;

	// Read
	struct proctal_linux_proc_maps_region current;
};

struct proctal_linux_proc_maps_region_check {
	// PID of the program that the region belongs to.
	pid_t pid;

	// Region mask.
	long mask;

	// Whether it's readable.
	int read;

	// Whether it's writable.
	int write;

	// Whether it's executable.
	int execute;
};

/*
 * Opens the maps file of a program.
 *
 * Returns 1 on success, 0 on failure.
 */
int proctal_linux_proc_maps_open(struct proctal_linux_proc_maps *maps, pid_t pid);

/*
 * Opens a maps file.
 *
 * Returns 1 on success, 0 on failure.
 */
int proctal_linux_proc_maps_fopen(struct proctal_linux_proc_maps *maps, const char *path);

/*
 * Closes a maps file.
 */
void proctal_linux_proc_maps_close(struct proctal_linux_proc_maps *maps);

/*
 * Reads an entry from the maps file.
 *
 * Returns a pointer to a proctal_linux_proc_maps_region struct if it
 * successfully read an entry or NULL if not.
 *
 * The pointer is valid until the next call to this function or when the maps
 * file is called.
 */
struct proctal_linux_proc_maps_region *proctal_linux_proc_maps_read(struct proctal_linux_proc_maps *maps);

/*
 * Checks whether a region passes.
 */
int proctal_linux_proc_maps_region_check(struct proctal_linux_proc_maps_region *region, struct proctal_linux_proc_maps_region_check *check);

const struct proctal_darr *proctal_linux_proc_path(pid_t pid, const char *file);

void proctal_linux_proc_path_dispose(const struct proctal_darr *path);

const struct proctal_darr *proctal_linux_program_path(pid_t pid);

void proctal_linux_program_path_dispose(const struct proctal_darr *path);

const struct proctal_darr *proctal_linux_task_ids(pid_t pid);

void proctal_linux_task_ids_dispose(const struct proctal_darr *tids);

#endif /* API_LINUX_PROC_H */

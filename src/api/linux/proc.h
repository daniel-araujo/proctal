#ifndef API_LINUX_PROC_H
#define API_LINUX_PROC_H

#include <stdio.h>
#include <sys/types.h>
#include <darr.h>

struct proctal_linux_mem_region {
	void *start_addr;
	void *end_addr;

	int read;
	int write;
	int execute;

	// This is not perfect.
	char path[255];
};

struct darr *proctal_linux_proc_path(pid_t pid, const char *file);

void proctal_linux_proc_path_dispose(struct darr *path);

int proctal_linux_read_mem_region(struct proctal_linux_mem_region *region, FILE *maps);

struct darr *proctal_linux_program_path(pid_t pid);

void proctal_linux_program_path_dispose(struct darr *path);

struct darr *proctal_linux_task_ids(pid_t pid);

void proctal_linux_task_ids_dispose(struct darr *tids);

#endif /* API_LINUX_PROC_H */

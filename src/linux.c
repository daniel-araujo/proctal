#include <stdio.h>
#include <sys/types.h>

#include "linux.h"

#define PID_MAX_DIGITS 5
#define PROC_FILE_MAX 40

const char *proctal_linux_proc_path(pid_t pid, const char *file)
{
	const char *path_template = "/proc/%d/%s";
	static char path[sizeof(path_template) + PID_MAX_DIGITS + PROC_FILE_MAX];

	int e = snprintf(path, sizeof path, path_template, pid, file);
	path[e] = '\0';

	return path;
}

int proctal_linux_read_mem_region(struct proctal_linux_mem_region *region, FILE *maps)
{
	return -1;
}

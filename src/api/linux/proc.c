#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "magic/magic.h"
#include "api/linux/proctal.h"
#include "api/linux/proc.h"

const struct proctal_darr *proctal_linux_proc_path(pid_t pid, const char *file)
{
#define PID_MAX_DIGITS 5

	static char proc_dir[] = "/proc";

	struct proctal_darr *path = proctal_global_malloc(sizeof(struct proctal_darr));

	if (path == NULL) {
		return NULL;
	}

	size_t file_size = strlen(file);

	proctal_darr_init(path, sizeof(char));
	proctal_darr_resize(path, ARRAY_SIZE(proc_dir) + 1 + PID_MAX_DIGITS + 1 + file_size + 1);

	int n = snprintf(
		proctal_darr_data(path),
		proctal_darr_size(path),
		"%s/%d/%s",
		proc_dir,
		pid,
		file);

	if (!(n > 0 && n < (int) (proctal_darr_size(path) - 1))) {
		proctal_darr_deinit(path);
		proctal_global_free(path);
		return NULL;
	}

	if (n < (int) proctal_darr_size(path)) {
		// Discards extra space.
		proctal_darr_resize(path, n);
	}

	return path;

#undef PID_MAX_DIGITS
}

void proctal_linux_proc_path_dispose(const struct proctal_darr *path)
{
	proctal_darr_deinit((struct proctal_darr *) path);
	proctal_global_free(path);
}

const struct proctal_darr *proctal_linux_program_path(pid_t pid)
{
	struct proctal_darr *path = proctal_global_malloc(sizeof(struct proctal_darr));

	if (path == NULL) {
		return NULL;
	}

	proctal_darr_init(path, sizeof(char));
	proctal_darr_resize(path, 255);
	char *path_data = proctal_darr_data(path);

	const struct proctal_darr *link = proctal_linux_proc_path(pid, "exe");
	size_t e = readlink(proctal_darr_data_const(link), path_data, proctal_darr_size(path) - 1);
	proctal_linux_proc_path_dispose(link);

	path_data[e] = '\0';

	return path;
}

void proctal_linux_program_path_dispose(const struct proctal_darr *path)
{
	proctal_darr_deinit((struct proctal_darr *) path);
	proctal_global_free(path);
}

const struct proctal_darr *proctal_linux_task_ids(pid_t pid)
{
	struct proctal_darr *tids = proctal_global_malloc(sizeof(struct proctal_darr));

	if (tids == NULL) {
		return NULL;
	}

	proctal_darr_init(tids, sizeof(pid_t));

	const struct proctal_darr *path = proctal_linux_proc_path(pid, "task");
	DIR *dir = opendir(proctal_darr_data_const(path));
	proctal_linux_proc_path_dispose(path);

	if (dir == NULL) {
		return NULL;
	}

	struct dirent *dirent;

	for (;;) {
		dirent = readdir(dir);

		if (dirent == NULL) {
			// We have traversed all.
			break;
		}

		if (dirent->d_name[0] == '.') {
			// Skipping special files.
			continue;
		}

		proctal_darr_resize(tids, proctal_darr_size(tids) + 1);
		pid_t *e = proctal_darr_element(tids, proctal_darr_size(tids) - 1);
		*e = atoi(dirent->d_name);
	}

	closedir(dir);

	return tids;
}

void proctal_linux_task_ids_dispose(const struct proctal_darr *tids)
{
	proctal_darr_deinit((struct proctal_darr *) tids);
	proctal_global_free(tids);
}

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "magic/magic.h"
#include "api/linux/proc.h"

struct darr *proctal_linux_proc_path(pid_t pid, const char *file)
{
#define PID_MAX_DIGITS 5

	static char proc_dir[] = "/proc";

	struct darr *path = malloc(sizeof(struct darr));

	if (path == NULL) {
		return NULL;
	}

	size_t file_size = strlen(file);

	darr_init(path, sizeof(char));
	darr_resize(path, ARRAY_SIZE(proc_dir) + 1 + PID_MAX_DIGITS + 1 + file_size + 1);

	int n = snprintf(
		darr_data(path),
		darr_size(path),
		"%s/%d/%s",
		proc_dir,
		pid,
		file);

	if (!(n > 0 && n < (int) (darr_size(path) - 1))) {
		darr_deinit(path);
		free(path);
		return NULL;
	}

	return path;

#undef PID_MAX_DIGITS
}

void proctal_linux_proc_path_dispose(struct darr *path)
{
	darr_deinit(path);
	free(path);
}

struct darr *proctal_linux_program_path(pid_t pid)
{
	struct darr *path = malloc(sizeof(struct darr));

	if (path == NULL) {
		return NULL;
	}

	darr_init(path, sizeof(char));
	darr_resize(path, 255);
	char *path_data = darr_data(path);

	struct darr *link = proctal_linux_proc_path(pid, "exe");
	size_t e = readlink(darr_data(link), path_data, darr_size(path) - 1);
	proctal_linux_proc_path_dispose(link);

	path_data[e] = '\0';

	return path;
}

void proctal_linux_program_path_dispose(struct darr *path)
{
	darr_deinit(path);
	free(path);
}

struct darr *proctal_linux_task_ids(pid_t pid)
{
	struct darr *tids = malloc(sizeof(struct darr));

	if (tids == NULL) {
		return NULL;
	}

	darr_init(tids, sizeof(pid_t));

	struct darr *path = proctal_linux_proc_path(pid, "task");
	DIR *dir = opendir(darr_data(path));
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

		darr_resize(tids, darr_size(tids) + 1);
		pid_t *e = darr_element(tids, darr_size(tids) - 1);
		*e = atoi(dirent->d_name);
	}

	closedir(dir);

	return tids;
}

void proctal_linux_task_ids_dispose(struct darr *tids)
{
	darr_deinit(tids);
	free(tids);
}

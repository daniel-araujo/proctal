#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "magic/magic.h"
#include "api/linux/proc.h"

static inline void mem_region_skip_space(FILE *maps)
{
	int ch;

	do {
		ch = fgetc(maps);

		if (ch == EOF) {
			return;
		}
	} while (ch == ' ');

	ungetc(ch, maps);
}

static inline void mem_region_skip_nl(FILE *maps)
{
	int ch;

	do {
		ch = fgetc(maps);

		if (ch == EOF) {
			return;
		}
	} while (ch == '\n');

	ungetc(ch, maps);
}

static inline void mem_region_skip_until_space(FILE *maps)
{
	int ch;

	do {
		ch = fgetc(maps);

		if (ch == EOF) {
			return;
		}
	} while (ch != ' ');

	ungetc(ch, maps);
}

static inline void mem_region_skip_until_nl(FILE *maps)
{
	int ch;

	do {
		ch = fgetc(maps);

		if (ch == EOF) {
			return;
		}
	} while (ch != '\n');

	ungetc(ch, maps);
}

static inline int mem_region_is_path_present(FILE *maps)
{
	int ch = fgetc(maps);
	int r = (ch != '\n');

	ungetc(ch, maps);

	return r;
}

static inline int read_until_nl(FILE *maps, char *buf, int max)
{
	int ch;
	int i = 0;

	do {
		ch = fgetc(maps);

		if (ch == EOF) {
			break;
		}

		if (ch == '\n') {
			ungetc(ch, maps);
			break;
		}

		buf[i++] = ch;
	} while (i < max);

	return i;
}

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
		darr_address(path, 0),
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

int proctal_linux_read_mem_region(struct proctal_linux_mem_region *region, FILE *maps)
{
	if (fscanf(maps, "%lx-%lx", (unsigned long *) &region->start_addr, (unsigned long *) &region->end_addr) != 2) {
		return -1;
	}

	mem_region_skip_space(maps);

	region->read = fgetc(maps) == 'r';
	region->write = fgetc(maps) == 'w';
	region->execute = fgetc(maps) == 'x';
	fgetc(maps); // Skipping over this one.

	for (int i = 0; i < 3; i++) {
		mem_region_skip_space(maps);
		mem_region_skip_until_space(maps);
	}

	if (mem_region_is_path_present(maps)) {
		mem_region_skip_space(maps);
		int read = read_until_nl(maps, region->path, sizeof(region->path) - 1);
		region->path[read] = '\0';
	}

	mem_region_skip_until_nl(maps);
	mem_region_skip_nl(maps);

	return 0;
}

struct darr *proctal_linux_program_path(pid_t pid)
{
	struct darr *path = malloc(sizeof(struct darr));

	if (path == NULL) {
		return NULL;
	}

	darr_init(path, sizeof(char));
	darr_resize(path, 255);
	char *path_data = darr_address(path, 0);

	struct darr *link = proctal_linux_proc_path(pid, "exe");
	size_t e = readlink(darr_address(link, 0), path_data, darr_size(path) - 1);
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
	DIR *dir = opendir(darr_address(path, 0));
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
		pid_t *e = darr_address(tids, darr_size(tids) - 1);
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

#include <stdio.h>
#include <sys/types.h>

#include <linux/proc.h>

#define PID_MAX_DIGITS 5
#define PROC_FILE_MAX 40

static inline void mem_region_skip_space(FILE *maps)
{
	int ch;

	do {
		ch = fgetc(maps);
	} while (ch != EOF && ch == ' ');

	ungetc(ch, maps);
}

static inline void mem_region_skip_until_space(FILE *maps)
{
	int ch;

	do {
		ch = fgetc(maps);
	} while (ch != EOF && ch != ' ');

	ungetc(ch, maps);
}

static inline int mem_region_is_path_present(FILE *maps)
{
	int ch = fgetc(maps);
	int r = (ch != '\n');

	ungetc(ch, maps);

	return r;
}

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
	if (fscanf(maps, "%lx-%lx", (unsigned long *) &region->start_addr, (unsigned long *) &region->end_addr) != 2) {
		return -1;
	}

	mem_region_skip_space(maps);

	region->read = fgetc(maps) == 'r';
	region->write = fgetc(maps) == 'w';
	region->execute = fgetc(maps) == 'x';
	fgetc(maps); // Skipping over this one.

	mem_region_skip_space(maps);

	for (int i = 0; i < 3; i++) {
		mem_region_skip_until_space(maps);
		mem_region_skip_space(maps);
	}

	if (mem_region_is_path_present(maps) && fscanf(maps, "%254s", region->path) != 1) {
		return -1;
	}

	return 0;
}

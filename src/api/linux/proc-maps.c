#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>

#include "magic/magic.h"
#include "api/linux/proctal.h"
#include "api/linux/proc.h"

static inline void skip_space(FILE *maps)
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

static inline void skip_nl(FILE *maps)
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

static inline void skip_until_space(FILE *maps)
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

static inline void skip_until_nl(FILE *maps)
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

static inline int is_there_more(FILE *maps)
{
	int ch = fgetc(maps);
	int r = (ch == ' ');

	ungetc(ch, maps);

	return r;
}

static inline void read_until_nl(FILE *maps, struct proctal_darr *buffer)
{
	proctal_darr_resize(buffer, 255);

	int ch;
	size_t i = 0;
	char *bufferbuf = proctal_darr_data(buffer);

	for (;;) {
		ch = fgetc(maps);

		if (ch == EOF) {
			break;
		}

		if (ch == '\n') {
			ungetc(ch, maps);
			break;
		}

		bufferbuf[i++] = ch;

		if (i > proctal_darr_size(buffer)) {
			proctal_darr_grow(buffer, proctal_darr_size(buffer));
			bufferbuf = proctal_darr_data(buffer);
		}
	}

	proctal_darr_resize(buffer, i + 1);
	bufferbuf = proctal_darr_data(buffer);
	bufferbuf[i] = '\0';
}

int proctal_linux_proc_maps_region_check(struct proctal_linux_proc_maps_region *region, struct proctal_linux_proc_maps_region_check *check)
{
	if (check->read) {
		if (!region->read) {
			return 0;
		}

		if (proctal_darr_size(&region->name) && strcmp(proctal_darr_data(&region->name), "[vvar]") == 0) {
			// Can't seem to read from this region regardless of it
			// being readable.
			return 0;
		}
	}

	if (check->write && !region->write) {
		return 0;
	}

	if (check->execute && !region->execute) {
		return 0;
	}

	if (check->mask) {
		if (check->mask & PROCTAL_REGION_STACK) {
			if (proctal_darr_size(&region->name) != 0 && strncmp(proctal_darr_data(&region->name), "[stack", 6) == 0) {
				return 1;
			}
		}

		if (check->mask & PROCTAL_REGION_HEAP) {
			if (proctal_darr_size(&region->name) != 0 && strcmp(proctal_darr_data(&region->name), "[heap]") == 0) {
				return 1;
			}
		}

		if (check->mask & PROCTAL_REGION_PROGRAM_CODE) {
			const struct proctal_darr *program_path = proctal_linux_program_path(check->pid);
			int same_path = strcmp(proctal_darr_data(&region->name), proctal_darr_data_const(program_path)) == 0;
			proctal_linux_program_path_dispose(program_path);

			if (same_path && region->execute) {
				return 1;
			}
		}

		return 0;
	}

	return 1;
}

int proctal_linux_proc_maps_open(struct proctal_linux_proc_maps *maps, pid_t pid)
{
	const struct proctal_darr *path = proctal_linux_proc_path(pid, "maps");
	int ret = proctal_linux_proc_maps_fopen(maps, proctal_darr_data_const(path));
	proctal_linux_proc_path_dispose(path);

	return ret;
}

int proctal_linux_proc_maps_fopen(struct proctal_linux_proc_maps *maps, const char *path)
{
	FILE *file = fopen(path, "r");

	if (file == NULL) {
		return 0;
	}

	maps->file = file;
	proctal_darr_init(&maps->current.name, sizeof(char));

	return 1;
}

void proctal_linux_proc_maps_close(struct proctal_linux_proc_maps *maps)
{
	fclose(maps->file);
	proctal_darr_deinit(&maps->current.name);
}

struct proctal_linux_proc_maps_region *proctal_linux_proc_maps_read(struct proctal_linux_proc_maps *maps)
{
	if (fscanf(maps->file, "%p-%p", &maps->current.start, &maps->current.end) != 2) {
		// Looks like it's over.
		return NULL;
	}

	skip_space(maps->file);

	maps->current.read = fgetc(maps->file) == 'r';
	maps->current.write = fgetc(maps->file) == 'w';
	maps->current.execute = fgetc(maps->file) == 'x';
	fgetc(maps->file); // Skipping over this one.

	for (int i = 0; i < 3; i++) {
		skip_space(maps->file);
		skip_until_space(maps->file);
	}

	if (is_there_more(maps->file)) {
		skip_space(maps->file);
		read_until_nl(maps->file, &maps->current.name);
	} else {
		skip_until_nl(maps->file);
		proctal_darr_resize(&maps->current.name, 0);
	}

	skip_nl(maps->file);

	return &maps->current;
}

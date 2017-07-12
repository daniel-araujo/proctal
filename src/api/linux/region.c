#include <stdio.h>
#include <string.h>

#include "api/linux/region.h"
#include "api/linux/proc.h"

static inline int interesting_region(struct proctal_linux *pl)
{
	if (pl->p.region.mask & PROCTAL_REGION_STACK) {
		if (strncmp(pl->region.curr.path, "[stack", 6) == 0) {
			return 1;
		}
	}

	if (pl->p.region.mask & PROCTAL_REGION_HEAP) {
		if (strcmp(pl->region.curr.path, "[heap]") == 0) {
			return 1;
		}
	}

	if (pl->p.region.mask & PROCTAL_REGION_PROGRAM_CODE) {
		struct darr *program_path = proctal_linux_program_path(pl->pid);
		int same_path = strcmp(pl->region.curr.path, darr_data(program_path)) == 0;
		proctal_linux_program_path_dispose(program_path);

		if (same_path && pl->region.curr.execute) {
			return 1;
		}
	}

	if (pl->p.region.mask != 0) {
		return 0;
	}

	if (pl->p.region.read) {
		if (!pl->region.curr.read) {
			return 0;
		}

		if (strcmp(pl->region.curr.path, "[vvar]") == 0) {
			// Can't seem to read from this region regardless of it
			// being readable.
			return 0;
		}
	}

	if (pl->p.region.write && !pl->region.curr.write) {
		return 0;
	}

	if (pl->p.region.execute && !pl->region.curr.execute) {
		return 0;
	}

	if (pl->p.region.mask == 0) {
		return 1;
	}

	return 0;
}

static inline int next_region(struct proctal_linux *pl)
{
	do {
		if (proctal_linux_read_mem_region(&pl->region.curr, pl->region.maps) != 0) {
			return 0;
		}
	} while (!interesting_region(pl));

	return 1;
}

static inline int has_started(struct proctal_linux *pl)
{
	return pl->region.maps != NULL;
}

static inline int has_finished(struct proctal_linux *pl)
{
	return pl->region.finished;
}

static int next(struct proctal_linux *pl)
{
	if (!has_started(pl)) {
		struct darr *path = proctal_linux_proc_path(pl->pid, "maps");
		pl->region.maps = fopen(darr_data(path), "r");
		proctal_linux_proc_path_dispose(path);

		if (pl->region.maps == NULL) {
			proctal_set_error(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
			return 0;
		}
	}

	if (!next_region(pl)) {
		fclose(pl->region.maps);
		pl->region.maps = NULL;
		pl->region.finished = 1;
		return 0;
	}

	return 1;
}

void proctal_linux_scan_region_start(struct proctal_linux *pl)
{
	if (pl->region.maps) {
		fclose(pl->region.maps);
		pl->region.maps = NULL;
	}

	pl->region.finished = 0;
}

void proctal_linux_scan_region_stop(struct proctal_linux *pl)
{
	if (pl->region.maps) {
		fclose(pl->region.maps);
		pl->region.maps = NULL;
	}
}

int proctal_linux_scan_region(struct proctal_linux *pl, void **start, void **end)
{
	if (has_finished(pl)) {
		return 0;
	}

	if (next(pl)) {
		*start = pl->region.curr.start_addr;
		*end = pl->region.curr.end_addr;
		return 1;
	} else {
		return 0;
	}
}

#include <string.h>

#include <linux/address.h>

static inline int interesting_region(struct proctal_linux *pl)
{
	if (pl->p.address.read) {
		if (!pl->address.region.read) {
			return 0;
		}

		if (strcmp(pl->address.region.path, "[vvar]") == 0) {
			// Can't seem to read from this region regardless of it
			// being readable.
			return 0;
		}
	}

	if (pl->p.address.write && !pl->address.region.write) {
		return 0;
	}

	if (pl->p.address.execute && !pl->address.region.execute) {
		return 0;
	}

	if (pl->p.address.region_mask == 0) {
		return 1;
	}

	if (pl->p.address.region_mask & PROCTAL_ADDR_REGION_STACK) {
		if (strncmp(pl->address.region.path, "[stack", 6) == 0) {
			return 1;
		}
	}

	if (pl->p.address.region_mask & PROCTAL_ADDR_REGION_HEAP) {
		if (strcmp(pl->address.region.path, "[heap]") == 0) {
			return 1;
		}
	}

	return 0;
}

static inline int has_reached_region_end(struct proctal_linux *pl)
{
	return ((void *) ((char *) pl->address.curr + pl->p.address.size)) > pl->address.region.end_addr;
}

static inline int next_region(struct proctal_linux *pl)
{
	for (;;) {
		if (proctal_linux_read_mem_region(&pl->address.region, pl->address.maps) != 0) {
			return 0;
		}

		if (!interesting_region(pl)) {
			continue;
		}

		pl->address.curr = proctal_align_addr(pl->address.region.start_addr, pl->p.address.align);

		// After applying the correct alignment to the address, it is
		// possible to have reached the end of the memory region. Even
		// if this is very unlikely to happen, this situation must be
		// checked nonetheless.
		if (!has_reached_region_end(pl)) {
			break;
		}
	}

	return 1;
}

static inline int has_started(struct proctal_linux *pl)
{
	return pl->address.started;
}

static inline int has_finished(struct proctal_linux *pl)
{
	return pl->address.started && pl->address.curr == NULL;
}

static int first(struct proctal_linux *pl)
{
	pl->address.maps = fopen(proctal_linux_proc_path(pl->pid, "maps"), "r");

	if (pl->address.maps == NULL) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		return 0;
	}

	if (!next_region(pl)) {
		fclose(pl->address.maps);
		pl->address.maps = NULL;
		return 0;
	}

	return 1;
}

static int next(struct proctal_linux *pl)
{
	pl->address.curr = (void *) ((char *) pl->address.curr + pl->p.address.align);

	if (has_reached_region_end(pl) && !next_region(pl)) {
		fclose(pl->address.maps);
		pl->address.curr = NULL;
		return 0;
	}

	return 1;
}

void proctal_linux_address_new(struct proctal_linux *pl)
{
	if (pl->address.maps) {
		fclose(pl->address.maps);
		pl->address.maps = NULL;
	}

	pl->address.curr = NULL;
	pl->address.started = 0;
}

int proctal_linux_address(struct proctal_linux *pl, void **addr)
{
	if (!has_started(pl)) {
		pl->address.started = 1;

		if (!first(pl)) {
			return 0;
		}

		*addr = pl->address.curr;
		return 1;
	} else if (has_finished(pl)) {
		return 0;
	}

	if (next(pl)) {
		*addr = pl->address.curr;
		return 1;
	} else {
		return 0;
	}
}

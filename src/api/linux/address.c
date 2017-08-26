#include <string.h>

#include "api/linux/address.h"

/*
 * Helpful function for finding the next suitably aligned address relative to
 * the given one. Will return the given address if it's already aligned.
 *
 * This should be placed somewhere that can be accessible to the
 * rest of the code base when needed.
 */
static inline void *align_address(void *address, size_t align)
{
	ptrdiff_t offset = ((unsigned long) address % align);

	if (offset != 0) {
		offset = align - offset;
	}

	return (char *) address + offset;
}

static inline int is_over_the_region_end(struct proctal_linux *pl)
{
	void *address_end = (char *) pl->address.current_address + pl->p.address.size;

	return address_end > pl->address.current_region->end;
}

static inline void next_region(struct proctal_linux *pl)
{
	do {
		pl->address.current_region = proctal_linux_proc_maps_read(&pl->address.maps);

		if (pl->address.current_region == NULL) {
			// No more found.
			return;
		}
	} while (!proctal_linux_proc_maps_region_check(pl->address.current_region, &pl->address.region_check));

	pl->address.current_address = align_address(
		pl->address.current_region->start,
		pl->p.address.align);

	// After applying the correct alignment to the address, it is possible
	// to have reached the end of the memory region. Even if this is very
	// unlikely to happen, this situation must be checked nonetheless.
	if (is_over_the_region_end(pl)) {
		// Try again.
		next_region(pl);
	}
}

static inline void next_region_address(struct proctal_linux *pl)
{
	pl->address.current_address = (char *) pl->address.current_address + pl->p.address.align;

	if (is_over_the_region_end(pl)) {
		// No more found.
		pl->address.current_address = NULL;
	}
}

static int next(struct proctal_linux *pl)
{
	if (pl->address.current_region == NULL) {
		next_region(pl);
	} else {
		next_region_address(pl);

		if (pl->address.current_address == NULL) {
			next_region(pl);
		}
	}

	return pl->address.current_address == NULL;
}

void proctal_linux_scan_address_start(struct proctal_linux *pl)
{
	if (!proctal_linux_proc_maps_open(&pl->address.maps, pl->pid)) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		return;
	}

	pl->address.region_check.pid = pl->pid;
	pl->address.region_check.mask = pl->p.address.region_mask;
	pl->address.region_check.read = pl->p.address.read;
	pl->address.region_check.write = pl->p.address.write;
	pl->address.region_check.execute = pl->p.address.execute;

	pl->address.started = 1;
	pl->address.current_region = NULL;
	pl->address.current_address = NULL;
}

void proctal_linux_scan_address_stop(struct proctal_linux *pl)
{
	if (pl->address.started) {
		proctal_linux_proc_maps_close(&pl->address.maps);
	}

	pl->address.started = 0;
}

int proctal_linux_scan_address_next(struct proctal_linux *pl, void **addr)
{
	if (next(pl)) {
		*addr = pl->address.current_address;
		return 1;
	} else {
		return 0;
	}
}

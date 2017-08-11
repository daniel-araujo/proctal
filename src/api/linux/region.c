#include <stdio.h>
#include <string.h>

#include "api/linux/region.h"
#include "api/linux/proc.h"

static struct proctal_linux_proc_maps_region *next(struct proctal_linux *pl)
{
	struct proctal_linux_proc_maps_region *region;

	do {
		region = proctal_linux_proc_maps_read(&pl->region.maps);

		if (region == NULL) {
			// No more found.
			break;
		}
	} while (!proctal_linux_proc_maps_region_check(region, &pl->region.check));

	return region;
}

void proctal_linux_scan_region_start(struct proctal_linux *pl)
{
	if (!proctal_linux_proc_maps_open(&pl->region.maps, pl->pid)) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		return;
	}

	pl->region.check.pid = pl->pid;
	pl->region.check.mask = pl->p.region.mask;
	pl->region.check.read = pl->p.region.read;
	pl->region.check.write = pl->p.region.write;
	pl->region.check.execute = pl->p.region.execute;

	pl->region.started = 1;
}

void proctal_linux_scan_region_stop(struct proctal_linux *pl)
{
	if (pl->region.started) {
		proctal_linux_proc_maps_close(&pl->region.maps);
	}

	pl->region.started = 0;
}

int proctal_linux_scan_region(struct proctal_linux *pl, void **start, void **end)
{
	struct proctal_linux_proc_maps_region *region = next(pl);

	if (region) {
		*start = region->start;
		*end = region->end;
		return 1;
	} else {
		return 0;
	}
}

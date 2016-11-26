#include <string.h>

#include <linux/addr.h>

static inline int interesting_region(struct proctal_linux_addr_iter *iterl)
{
	if (iterl->iter.region_mask == 0) {
		return 1;
	}

	if (iterl->iter.region_mask & PROCTAL_ADDR_REGION_STACK) {
		if (strncmp(iterl->region.path, "[stack", 6) == 0) {
			return 1;
		}
	}

	if (iterl->iter.region_mask & PROCTAL_ADDR_REGION_HEAP) {
		if (strcmp(iterl->region.path, "[heap]") == 0) {
			return 1;
		}
	}

	return 0;
}

static inline int has_reached_region_end(struct proctal_linux_addr_iter *iterl)
{
	return ((void *) ((char *) iterl->iter.curr_addr + iterl->iter.size)) > iterl->region.end_addr;
}

static inline int next_region(struct proctal_linux_addr_iter *iterl)
{
	for (;;) {
		if (proctal_linux_read_mem_region(&iterl->region, iterl->maps) != 0) {
			return 0;
		}

		if (!interesting_region(iterl)) {
			continue;
		}

		iterl->iter.curr_addr = proctal_align_addr(iterl->region.start_addr, iterl->iter.align);

		// After applying the correct alignment to the address, it is
		// possible to have reached the end of the memory region. Even
		// if this is very unlikely to happen, this situation must be
		// checked nonetheless.
		if (!has_reached_region_end(iterl)) {
			break;
		}
	}

	return 1;
}

void proctal_linux_addr_iter_init(struct proctal_linux *pl, struct proctal_linux_addr_iter *iterl)
{
	proctal_addr_iter_init(&pl->p, &iterl->iter);

	iterl->pl = pl;
	iterl->maps = NULL;
}

void proctal_linux_addr_iter_deinit(struct proctal_linux *pl, struct proctal_linux_addr_iter *iterl)
{
	proctal_addr_iter_deinit(&pl->p, &iterl->iter);
}

int proctal_linux_addr_iter_first(struct proctal_linux_addr_iter *iterl)
{
	iterl->maps = fopen(proctal_linux_proc_path(iterl->pl->pid, "maps"), "r");

	if (iterl->maps == NULL) {
		proctal_set_error(&iterl->pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		return 0;
	}

	if (!next_region(iterl)) {
		fclose(iterl->maps);
		iterl->maps = NULL;
		return 0;
	}

	return 1;
}

int proctal_linux_addr_iter_next(struct proctal_linux_addr_iter *iterl)
{
	iterl->iter.curr_addr = (void *) ((char *) iterl->iter.curr_addr + iterl->iter.align);

	if (has_reached_region_end(iterl) && !next_region(iterl)) {
		fclose(iterl->maps);
		iterl->iter.curr_addr = NULL;
		return 0;
	}

	return 1;
}

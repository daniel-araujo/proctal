#include <stdlib.h>
#include <stdio.h>

#include "proctal.h"
#include "alloc.h"
#include "linux.h"

struct proctal_addr_iter {
	// Process ID.
	pid_t pid;
	// Start address of the next call.
	void *curr_addr;
	// Memory mappings of the address space.
	FILE *maps;
	// Current region being read.
	struct proctal_linux_mem_region region;
	// Address alignment.
	size_t align;
	// Size of the value of the address. We only want to return addresses
	// that when dereferenced can return values of up to this size.
	size_t size;
};

static inline int has_started(proctal_addr_iter iter)
{
	return iter->curr_addr != NULL;
}

static inline int has_ended(proctal_addr_iter iter)
{
	return iter->curr_addr != NULL && iter->maps == NULL;
}

static inline int has_reached_region_end(proctal_addr_iter iter)
{
	return ((void *) ((char *) iter->curr_addr + iter->size)) > iter->region.end_addr;
}

static inline void *align_addr(void *addr, size_t align)
{
	ptrdiff_t offset = ((unsigned long) addr % align);

	if (offset != 0) {
		offset = align - offset;
	}

	return (void *) ((char *) addr + offset);
}

static inline int next_region(proctal_addr_iter iter)
{
	do {
		if (proctal_linux_read_mem_region(&iter->region, iter->maps) != 0) {
			return 0;
		}

		iter->curr_addr = align_addr(iter->region.start_addr, iter->align);

		// After applying the correct alignment to the address, it is
		// possible to have reached the end of the memory region. Even
		// if this is very unlikely to happen, this situation must be
		// checked.
	} while (has_reached_region_end(iter));

	return 1;
}

static inline int next_address(proctal_addr_iter iter)
{
	if (iter->curr_addr == NULL) {
		return 0;
	}

	iter->curr_addr = (void *) ((char *) iter->curr_addr + iter->align);

	if (has_reached_region_end(iter) && !next_region(iter)) {
		return 0;
	}

	return 1;
}

static inline int start(proctal_addr_iter iter)
{
	iter->maps = fopen(proctal_linux_proc_path(iter->pid, "maps"), "r");

	if (iter->maps == NULL) {
		return -1;
	}

	if (!next_region(iter)) {
		fclose(iter->maps);
		iter->maps = NULL;
		return -1;
	}

	return 0;
}

proctal_addr_iter proctal_addr_iter_create(pid_t pid)
{
	proctal_addr_iter iter = proctal_alloc(sizeof *iter);

	if (iter == NULL) {
		return iter;
	}

	iter->pid = pid;
	iter->curr_addr = NULL;
	iter->maps = NULL;
	iter->size = 1;
	iter->align = 1;

	return iter;
}

void proctal_addr_iter_destroy(proctal_addr_iter iter)
{
	proctal_dealloc(iter);
}

size_t proctal_addr_iter_size(proctal_addr_iter iter)
{
	return iter->size;
}

void proctal_addr_iter_set_size(proctal_addr_iter iter, size_t size)
{
	iter->size = size > 0 ? size : 1;
}

size_t proctal_addr_iter_align(proctal_addr_iter iter)
{
	return iter->align;
}

void proctal_addr_iter_set_align(proctal_addr_iter iter, size_t align)
{
	iter->align = align > 0 ? align : 1;
}

int proctal_addr_iter_next(proctal_addr_iter iter, void **addr)
{
	if (!has_started(iter)) {
		if (start(iter) != 0) {
			return -1;
		}
	} else if (has_ended(iter)) {
		return 1;
	}

	*addr = iter->curr_addr;

	if (next_address(iter)) {
		return 0;
	} else {
		fclose(iter->maps);
		return 1;
	}
}

#include <stdlib.h>
#include <stdio.h>

#include "proctal.h"
#include "alloc.h"
#include "linux.h"

struct proctal_search_state {
	// Start address of the next call.
	void *curr_addr;
	// Memory mappings of the address space.
	FILE *maps;
	// Current region being read.
	struct proctal_linux_mem_region region;
};

struct proctal_search_options {
	// How many characters to read from the start address.
	size_t size;
	// Address alignment.
	size_t align;
};

static inline int has_search_started(proctal_search_state state)
{
	return state->curr_addr != NULL;
}

static inline int has_search_ended(proctal_search_state state)
{
	return state->curr_addr != NULL && state->maps == NULL;
}

static inline int has_reached_region_end(proctal_search_state state, proctal_search_options options)
{
	return ((void *) ((char *) state->curr_addr + options->size)) > state->region.end_addr;
}

static inline void *align_addr(void *addr, size_t align)
{
	ptrdiff_t offset = ((unsigned long) addr % align);

	if (offset != 0) {
		offset = align - offset;
	}

	return (void *) ((char *) addr + offset);
}

static inline int next_region(proctal_search_state state, proctal_search_options options)
{
	do {
		if (proctal_linux_read_mem_region(&state->region, state->maps) != 0) {
			return 0;
		}

		state->curr_addr = align_addr(state->region.start_addr, options->align);

		// After applying the correct alignment to the address, it is
		// possible to have reached the end of the memory region. Even
		// if this is very unlikely to happen, this situation must be
		// checked.
	} while (has_reached_region_end(state, options));

	return 1;
}

static inline int next_address(proctal_search_state state, proctal_search_options options)
{
	if (state->curr_addr == NULL) {
		return 0;
	}

	state->curr_addr = (void *) ((char *) state->curr_addr + options->align);

	if (has_reached_region_end(state, options) && !next_region(state, options)) {
		return 0;
	}

	return 1;
}

static inline int start_search(pid_t pid, proctal_search_state state, proctal_search_options options)
{
	state->maps = fopen(proctal_linux_proc_path(pid, "maps"), "r");

	if (state->maps == NULL) {
		return -1;
	}

	if (!next_region(state, options)) {
		fclose(state->maps);
		state->maps = NULL;
		return -1;
	}

	return 0;
}

proctal_search_state proctal_search_state_create()
{
	proctal_search_state state = proctal_alloc(sizeof *state);

	if (state == NULL) {
		return state;
	}

	state->curr_addr = NULL;
	state->maps = NULL;

	return state;
}

void proctal_search_state_delete(proctal_search_state state)
{
	proctal_dealloc(state);
}

proctal_search_options proctal_search_options_create()
{
	proctal_search_options options = proctal_alloc(sizeof *options);

	if (options == NULL) {
		return options;
	}

	options->size = 1;
	options->align = 1;

	return options;
}

size_t proctal_search_options_size(proctal_search_options options)
{
	return options->size;
}

void proctal_search_options_set_size(proctal_search_options options, size_t size)
{
	options->size = size > 0 ? size : 1;
}

size_t proctal_search_options_align(proctal_search_options options)
{
	return options->align;
}

void proctal_search_options_set_align(proctal_search_options options, size_t align)
{
	options->align = align > 0 ? align : 1;
}

void proctal_search_options_delete(proctal_search_options options)
{
	proctal_dealloc(options);
}

int proctal_search(
	pid_t pid,
	proctal_search_state state,
	proctal_search_options options,
	void **addr,
	void *value)
{
	if (!has_search_started(state)) {
		if (start_search(pid, state, options) != 0) {
			return -1;
		}
	} else if (has_search_ended(state)) {
		return 0;
	}

	*addr = state->curr_addr;
	proctal_read(pid, state->curr_addr, (char *) value, options->size);

	if (next_address(state, options)) {
		return 1;
	} else {
		fclose(state->maps);
		return 0;
	}
}

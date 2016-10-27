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
};

static inline int has_search_started(proctal_search_state state)
{
	return state->curr_addr != NULL;
}

static inline int has_search_ended(proctal_search_state state)
{
	return state->curr_addr != NULL && state->maps == NULL;
}

static inline int has_reached_region_end(proctal_search_state state)
{
	return state->curr_addr >= state->region.end_addr;
}

static inline int start_search(pid_t pid, proctal_search_state state)
{
	state->maps = fopen(proctal_linux_proc_path(pid, "maps"), "r");

	if (state->maps == NULL) {
		return -1;
	}

	if (proctal_linux_read_mem_region(&state->region, state->maps) != 0) {
		fclose(state->maps);
		state->maps = NULL;
		return -1;
	}

	state->curr_addr = state->region.start_addr;

	return 0;
}

static inline int next_region(proctal_search_state state)
{
	if (proctal_linux_read_mem_region(&state->region, state->maps) != 0) {
		return 0;
	}

	state->curr_addr = state->region.start_addr;

	return 1;
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

	options->size = sizeof (int);

	return options;
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
		if (start_search(pid, state) != 0) {
			return -1;
		}
	} else if (has_search_ended(state)) {
		return 0;
	}

	*addr = state->curr_addr;
	proctal_read(pid, state->curr_addr, (char *) value, options->size);

	state->curr_addr = (void *) ((char *) state->curr_addr + options->size);

	if (has_reached_region_end(state) && !next_region(state)) {
		fclose(state->maps);
		return 0;
	} else {
		return 1;
	}
}

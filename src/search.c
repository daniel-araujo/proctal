#include <stdlib.h>
#include <stdio.h>

#include "proctal.h"
#include "alloc.h"
#include "linux.h"

struct proctal_search_state {
	// Start address of the next call.
	void *curraddr;
	// Process memory address space.
	FILE *mem;
	// Memory mappings of the address space.
	FILE *maps;
};

struct proctal_search_options {
	// How many characters to read from the start address.
	size_t size;
};

proctal_search_state proctal_search_state_create()
{
	proctal_search_state state = proctal_alloc(sizeof *state);

	if (state == NULL) {
		return state;
	}

	state->curraddr = NULL;
	state->mem = NULL;
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
	state->mem = fopen(proctal_linux_proc_path(pid, "mem"), "r");

	if (state->mem == NULL) {
		return -1;
	}

	state->maps = fopen(proctal_linux_proc_path(pid, "maps"), "r");

	if (state->maps == NULL) {
		state->mem = NULL;
		return -1;
	}

	fclose(state->mem);
	fclose(state->maps);

	return 0;
}

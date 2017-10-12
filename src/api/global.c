#include <stdlib.h>

#include "api/darr/darr.h"
#include "api/proctal.h"
#include "api/darr/memory-support.h"

struct proctal_global proctal_global = {
	.malloc = malloc,
	.free = free
};

void proctal_malloc_set(void *(*f)(size_t))
{
	if (f == NULL) {
		f = malloc;
		proctal_darr_global_realloc_set(realloc);
	} else {
		proctal_darr_global_realloc_set(proctal_darr_global_realloc);
	}

	proctal_global.malloc = f;
}

void proctal_free_set(void (*f)(void *))
{
	if (f == NULL) {
		f = free;
		proctal_darr_global_free_set(free);
	} else {
		proctal_darr_global_free_set(proctal_darr_global_free);
	}

	proctal_global.free = f;
}

extern inline void *proctal_global_malloc(size_t size);

extern inline void proctal_global_free(const void *address);

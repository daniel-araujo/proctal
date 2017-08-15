#include <stdlib.h>

#include "api/proctal.h"

struct proctal_global proctal_global = {
	.malloc = malloc,
	.free = free
};

void proctal_malloc_set(void *(*f)(size_t))
{
	if (f == NULL) {
		f = malloc;
	}

	proctal_global.malloc = f;
}

void proctal_free_set(void (*f)(void *))
{
	if (f == NULL) {
		f = free;
	}

	proctal_global.free = f;
}

void *proctal_global_malloc(size_t size);
void proctal_global_free(void *addr);

#include "lib/proctal.h"

void proctal_set_malloc(proctal p, void *(*malloc)(size_t))
{
	p->malloc = malloc;
}

void proctal_set_free(proctal p, void (*free)(void *))
{
	p->free = free;
}

void *proctal_malloc(proctal p, size_t size)
{
	void *a = p->malloc(size);

	if (a == NULL) {
		proctal_set_error(p, PROCTAL_ERROR_OUT_OF_MEMORY);
	}

	return a;
}

void proctal_free(proctal p, void *addr)
{
	return p->free(addr);
}

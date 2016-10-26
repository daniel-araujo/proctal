#include <stdlib.h>

#include "proctal.h"
#include "linux.h"

static proctal_malloc a = malloc;
static proctal_free d = free;

void proctal_set_malloc(proctal_malloc new)
{
	if (new == NULL) {
		a = malloc;
	}

	a = new;
}

void proctal_set_free(proctal_free new)
{
	if (new == NULL) {
		d = free;
	}

	d = new;
}

void *proctal_alloc(size_t size)
{
	return a(size);
}

void proctal_dealloc(void *addr)
{
	return d(addr);
}

#include <stdlib.h>

#include "proctal.h"

void *(*a)(size_t) = malloc;
void (*b)(void *) = free;

void proctal_global_set_malloc(void *(*malloc)(size_t))
{
	if (malloc == NULL) {
		a = malloc;
	}

	a = malloc;
}

void proctal_global_set_free(void (*free)(void *))
{
	if (free == NULL) {
		b = free;
	}

	b = free;
}

void *(*proctal_global_malloc())(size_t)
{
	return a;
}

void (*proctal_global_free())(void *)
{
	return b;
}

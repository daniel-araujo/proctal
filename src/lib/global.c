#include <stdlib.h>

#include "internal.h"
#include "global.h"

static void *(*a)(size_t) = malloc;
static void (*b)(void *) = free;

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

void *(*proctal_global_malloc(void))(size_t)
{
	return a;
}

void (*proctal_global_free(void))(void *)
{
	return b;
}

#include "api/proctal.h"

void *proctal_malloc(struct proctal *p, size_t size)
{
	void *a = proctal_global_malloc(size);

	if (a == NULL) {
		proctal_error_set(p, PROCTAL_ERROR_OUT_OF_MEMORY);
	}

	return a;
}

void proctal_free(struct proctal *p, const void *address)
{
	return proctal_global_free(address);
}

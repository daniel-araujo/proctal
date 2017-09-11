#include <stdlib.h>

#include "api/proctal.h"

int proctal_error(struct proctal *p)
{
	if (p == NULL) {
		return PROCTAL_ERROR_OUT_OF_MEMORY;
	}

	return p->error;
}

void proctal_error_set(struct proctal *p, int error)
{
	p->error = error;
}

int proctal_error_recover(struct proctal *p)
{
	if (p == NULL) {
		// No way to recover from that.
		return 0;
	}

	p->error = 0;
	return 1;
}

#include <stdio.h>

#include "api/darr/memory-support.h"
#include "api/darr/tests/realloc/util/block-size.h"

int main(void)
{
	int *i = proctal_darr_global_realloc(NULL, sizeof(int) * 2);

	i[0] = 12345;
	i[1] = 54321;

	int *i2 = proctal_darr_global_realloc(i, sizeof(int));

	if (i2 == NULL) {
		fprintf(stderr, "Unexpectedly returned NULL.\n");
		return 1;
	}

	if (block_size(i2) != sizeof(int)) {
		fprintf(stderr, "Expected to create a new block.\n");
		return 1;
	}

	if (*i2 != 12345) {
		fprintf(stderr, "Original value was lost.\n");
		return 1;
	}

	proctal_darr_global_free(i2);
	return 0;
}

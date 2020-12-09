#include <stdio.h>

#include "api/darr/memory-support.h"
#include "api/darr/tests/util/block-size.h"

int main(void)
{
	int *i = proctal_darr_global_realloc(NULL, sizeof(int));

	*i = 12345;

	int *i2 = proctal_darr_global_realloc(i, sizeof(int) * 2);

	if (i2 == NULL) {
		// Under normal conditions this should allocate a new block.
		fprintf(stderr, "Failed to allocate a new block.\n");
		return 1;
	}

	if (block_size(i2) != sizeof(int) * 2) {
		fprintf(stderr, "Wrong block size.\n");
		return 1;
	}

	if (*i2 != 12345) {
		fprintf(stderr, "Original value was lost.\n");
		return 1;
	}

	proctal_darr_global_free(i2);

	return 0;
}

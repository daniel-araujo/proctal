#include <stdio.h>

#include "api/darr/memory-support.h"
#include "api/darr/tests/realloc/util/block-size.h"

int main(void)
{
	int *i = proctal_darr_global_realloc(NULL, sizeof(int) * 3);

	i[0] = 12345;
	i[1] = 54321;
	i[2] = 33333;

	int *i2 = proctal_darr_global_realloc(i, sizeof(int) * 2);

	if (i2 == NULL) {
		fprintf(stderr, "Unexpectedly returned NULL.\n");
		return 1;
	}

	if (block_size(i2) != sizeof(int) * 2) {
		fprintf(stderr, "Did not expect to create a new block.\n");
		return 1;
	}

	if (i2[0] != 12345 || i2[1] != 54321) {
		fprintf(stderr, "Original value was lost.\n");
		return 1;
	}

	// Should be able to safely write an int to it.
	i2[0] = 0;
	i2[1] = 0;

	proctal_darr_global_free(i2);
	return 0;
}

#include <stdio.h>

#include "api/darr/memory-support.h"
#include "api/darr/tests/util/block-size.h"

int main(void)
{
	int *i = proctal_darr_global_realloc(NULL, sizeof(int));

	if (i == NULL) {
		// Under normal conditions this should allocate a new block.
		fprintf(stderr, "Failed to allocate a new block.\n");
		return 1;
	}

	if (block_size(i) != sizeof(int)) {
		fprintf(stderr, "Wrong block size.\n");
		return 1;
	}

	// Should be able to safely write an int to it.
	*i = 0;

	proctal_darr_global_free(i);
	return 0;
}

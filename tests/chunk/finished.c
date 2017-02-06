#include <stdio.h>

#include "chunk/chunk.h"

int main(void)
{
	char block[3];

	struct chunk c;
	chunk_init(&c, block, block + 3, 2);

	if (chunk_finished(&c)) {
		fprintf(stderr, "Incorrectly reporting to have finished after init.\n");
		chunk_deinit(&c);
		return 1;
	}

	chunk_next(&c);

	if (chunk_finished(&c)) {
		fprintf(stderr, "Incorrectly reporting to have finished before the last chunk.\n");
		chunk_deinit(&c);
		return 1;
	}

	chunk_next(&c);

	if (!chunk_finished(&c)) {
		fprintf(stderr, "Not reporting to have finished after last chunk.\n");
		chunk_deinit(&c);
		return 1;
	}

	chunk_deinit(&c);

	return 0;
}

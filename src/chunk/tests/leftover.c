#include <stdlib.h>
#include <stdio.h>

#include "chunk/chunk.h"

int main(void)
{
	char block[10];

	struct chunk c;
	chunk_init(&c, block, block + 10, 4);

	char *offset;
	size_t size;

	offset = chunk_offset(&c);
	size = chunk_size(&c);

	if (offset != &block[0]) {
		fprintf(stderr, "First chunk was supposed to start at the beginning of the block.\n");
		chunk_deinit(&c);
		return 1;
	}

	if (size != 4) {
		fprintf(stderr, "First chunk size is not correct.\n");
		chunk_deinit(&c);
		return 1;
	}

	if (!chunk_next(&c)) {
		fprintf(stderr, "There's supposed to be another chunk.\n");
		chunk_deinit(&c);
		return 1;
	}

	offset = chunk_offset(&c);
	size = chunk_size(&c);

	if (offset != &block[4]) {
		fprintf(stderr, "Middle chunk was supposed to start at the 4th element of the block.\n");
		chunk_deinit(&c);
		return 1;
	}

	if (size != 4) {
		fprintf(stderr, "Middle chunk size is not correct.\n");
		chunk_deinit(&c);
		return 1;
	}

	if (!chunk_next(&c)) {
		fprintf(stderr, "Last chunk is missing.\n");
		chunk_deinit(&c);
		return 1;
	}

	offset = chunk_offset(&c);
	size = chunk_size(&c);

	if (offset != &block[8]) {
		fprintf(stderr, "Last chunk was supposed to start at the 8th element of the block.\n");
		chunk_deinit(&c);
		return 1;
	}

	if (size != 2) {
		fprintf(stderr, "Last chunk size is not correct.\n");
		fprintf(stderr, "Expected 2, got %d.\n", (int) size);
		chunk_deinit(&c);
		return 1;
	}

	if (chunk_next(&c)) {
		fprintf(stderr, "There's not supposed to be any more chunks.\n");
		chunk_deinit(&c);
		return 1;
	}

	chunk_deinit(&c);

	return 0;
}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "src/riter/riter.h"

/*
 * Region of memory that is going to be iterated over.
 */
char memory[] = {
	0, 0, 0, 0,
	1, 2, 3, 4,
	5, 5, 5,
};

static void test_only_reads_aligned_data(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		// The source address will start at an incorrect alignment boundary.
		.source = memory + 1,
		.source_size = sizeof(memory),
		.buffer_size = 4,
		.data_align = 2,
		.data_size = 2,
	});

	size_t index = riter_index(&riter);

	if (index != 1) {
		fprintf(stderr, "Index should start at 1, it is %zu instead\n", index);
		abort();
	}

	riter_deinit(&riter);
}

static void test_aligned_data_even_when_they_overlap(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = 3,
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
	});
	assert(riter_index(&riter) == 0);

	assert(riter_next(&riter));
	assert(riter_index(&riter) == 1);

	assert(riter_next(&riter) == 0);
	assert(riter_end(&riter));

	riter_deinit(&riter);
}

int main(void)
{
	test_only_reads_aligned_data();
	test_aligned_data_even_when_they_overlap();
}

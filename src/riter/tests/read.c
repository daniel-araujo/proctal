#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "riter/riter.h"

/*
 * Region of memory that is going to be iterated over.
 */
char memory[] = {
	0, 0, 0, 0,
	1, 2, 3, 4,
	5, 5, 5,
};

static void test_index_should_start_at_zero(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
	});

	size_t index = riter_index(&riter);

	if (index != 0) {
		fprintf(stderr, "Index should start at 0, it is %zu instead\n", index);
		abort();
	}

	riter_deinit(&riter);
}

static void test_index_should_stop_at_last_index_that_can_hold_data_size(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
		.data_align = 2,
		.data_size = 2,
	});

	// This index cannot be iterated over because it only holds 1 byte and we
	// have requested data sizes of 2.
#define INVALID_LAST_INDEX 10

	// This is the expected last index.
#define VALID_LAST_INDEX 8

	// After the while loop, this variable will hold the last index.
	size_t index = 0;

	while (!riter_end(&riter)) {
		index = riter_index(&riter);
		riter_next(&riter);
	}

	if (index == INVALID_LAST_INDEX) {
		fprintf(stderr, "Reached index that cannot hold data size.\n");
		abort();
	}

	if (index != VALID_LAST_INDEX) {
		fprintf(stderr, "Did not end on the last valid index. Stopped at %zu.\n", index);
		abort();
	}

	riter_deinit(&riter);

#undef VALID_LAST_INDEX

#undef INVALID_LAST_INDEX
}

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
}

static void test_read_data(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
		.data_align = 2,
		.data_size = 2,
	});

	while (!riter_end(&riter)) {
		size_t index = riter_index(&riter);
		char *data = riter_data(&riter);

		if (data[0] != memory[index]) {
			fprintf(stderr, "Read index %zu incorrectly.\n", index);
			abort();
		}

		if (data[1] != memory[index + 1]) {
			fprintf(stderr, "Read index %zu incorrectly.\n", index);
			abort();
		}

		riter_next(&riter);
	}

	riter_deinit(&riter);
}

// Making sure that implementation details do not skip valid memory addresses
// between chunks.
static void test_does_not_skip_data_between_chunks(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
	});

	if (riter_index(&riter) != 0) {
		fprintf(stderr, "Expected index 0 but got %zu.\n", riter_index(&riter));
		abort();
	}

	assert(riter_next(&riter));

	if (riter_index(&riter) != 1) {
		fprintf(stderr, "Expected index 1 but got %zu.\n", riter_index(&riter));
		abort();
	}

	assert(riter_next(&riter));

	if (riter_index(&riter) != 2) {
		fprintf(stderr, "Expected index 2 but got %zu.\n", riter_index(&riter));
		abort();
	}

	riter_deinit(&riter);
}

int main(void)
{
	test_index_should_start_at_zero();
	test_index_should_stop_at_last_index_that_can_hold_data_size();
	test_only_reads_aligned_data();
	test_read_data();
	test_does_not_skip_data_between_chunks();
}

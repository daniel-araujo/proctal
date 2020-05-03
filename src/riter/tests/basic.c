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

static void test_init_fails_source_required(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source_size = sizeof(memory),
		.buffer_size = 4,
	});

	assert(srch_error(&srch) == SRCH_ERROR_SOURCE_REQUIRED);

	srch_deinit(&srch);
}

static void test_init_fails_source_size_required(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source = memory,
		.buffer_size = 4,
	});

	assert(srch_error(&srch) == SRCH_ERROR_SOURCE_SIZE_REQUIRED);

	srch_deinit(&srch);
}

static void test_init_fails_buffer_size_required(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source = memory,
		.source_size = sizeof(memory),
	});

	assert(srch_error(&srch) == SRCH_ERROR_BUFFER_SIZE_REQUIRED);

	srch_deinit(&srch);
}

static void test_init_fails_data_size_larger_than_buffer_size(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 1,
		.data_size = 2,
	});

	assert(srch_error(&srch) == SRCH_ERROR_DATA_SIZE_LARGER_THAN_BUFFER_SIZE);

	srch_deinit(&srch);
}

static void test_default_align_is_1(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
	});

	assert(srch_data_align(&srch) == 1);

	srch_deinit(&srch);
}

static void test_default_size_is_1(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
	});

	assert(srch_data_size(&srch) == 1);

	srch_deinit(&srch);
}

static void test_index_should_start_at_zero(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
	});

	size_t index = srch_index(&srch);

	if (index != 0) {
		printf("Index should start at 0, it is %zu instead\n", index);
		abort();
	}

	srch_deinit(&srch);
}

static void test_index_should_stop_at_last_index_that_can_hold_data_size(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
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
	size_t index;

	while (!srch_end(&srch)) {
		index = srch_index(&srch);
		srch_next(&srch);
	}

	if (index == INVALID_LAST_INDEX) {
		printf("Reached index that cannot hold data size.\n");
		abort();
	}

	if (index != VALID_LAST_INDEX) {
		printf("Did not end on the last valid index. Stopped at %zu.\n", index);
		abort();
	}

	srch_deinit(&srch);

#undef VALID_LAST_INDEX

#undef INVALID_LAST_INDEX
}

static void test_only_reads_aligned_data(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		// The source address will start at an incorrect alignment boundary.
		.source = memory + 1,
		.source_size = sizeof(memory),
		.buffer_size = 4,
		.data_align = 2,
		.data_size = 2,
	});

	size_t index = srch_index(&srch);

	if (index != 1) {
		printf("Index should start at 1, it is %zu instead\n", index);
		abort();
	}
}

static void test_read_data(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
		.data_align = 2,
		.data_size = 2,
	});

	while (!srch_end(&srch)) {
		size_t index = srch_index(&srch);
		char *data = srch_data(&srch);

		if (data[0] != memory[index]) {
			printf("Read index %zu incorrectly.\n", index);
			abort();
		}

		if (data[1] != memory[index + 1]) {
			printf("Read index %zu incorrectly.\n", index);
			abort();
		}

		srch_next(&srch);
	}

	srch_deinit(&srch);
}

// Making sure that implementation details do not skip valid memory addresses
// between chunks.
static void test_does_not_skip_data_between_chunks(void)
{
	struct srch srch;

	srch_init(&srch, &(struct srch_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
	});

	if (srch_index(&srch) != 0) {
		printf("Expected index 0 but got %zu.\n", srch_index(&srch));
		abort();
	}

	assert(srch_next(&srch));

	if (srch_index(&srch) != 1) {
		printf("Expected index 1 but got %zu.\n", srch_index(&srch));
		abort();
	}

	assert(srch_next(&srch));

	if (srch_index(&srch) != 2) {
		printf("Expected index 2 but got %zu.\n", srch_index(&srch));
		abort();
	}

	srch_deinit(&srch);
}

int main(void)
{
	test_init_fails_source_required();
	test_init_fails_source_size_required();
	test_init_fails_buffer_size_required();
	test_init_fails_data_size_larger_than_buffer_size();
	test_default_align_is_1();
	test_default_size_is_1();
	test_index_should_start_at_zero();
	test_index_should_stop_at_last_index_that_can_hold_data_size();
	test_only_reads_aligned_data();
	test_read_data();
	test_does_not_skip_data_between_chunks();
}

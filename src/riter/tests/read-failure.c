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

static int reader_always_fails(void *user, void *src, void *out, size_t size)
{
	return 0;
}

static int reader_fails_second(void *user, void *src, void *out, size_t size)
{
	static int called = 0;
	memcpy(src, out, size);
	return ++called == 2 ? 0 : 1;
}

// Checking that riter_error returns an error when reading fails in riter_init
static void test_init_read_failure_sets_error(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.reader = reader_always_fails,
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
	});

	assert(riter_error(&riter) == RITER_ERROR_READ_FAILURE);

	riter_deinit(&riter);
}

// Checking that riter_error returns an error when reading fails in riter_next
static void test_next_read_failure_sets_error(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.reader = reader_fails_second,
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
	});

	assert(riter_next(&riter) == 0);
	assert(riter_error(&riter) == RITER_ERROR_READ_FAILURE);

	riter_deinit(&riter);
}

int main(void)
{
	test_init_read_failure_sets_error();
	test_next_read_failure_sets_error();
}

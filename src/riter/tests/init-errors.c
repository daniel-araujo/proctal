#include <assert.h>

#include "riter/riter.h"

char memory[] = {
	0, 0, 0, 0,
	1, 2, 3, 4,
	5, 5, 5,
};

static void test_init_fails_source_required(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source_size = sizeof(memory),
		.buffer_size = 4,
	});

	assert(riter_error(&riter) == RITER_ERROR_SOURCE_REQUIRED);

	riter_deinit(&riter);
}

static void test_init_fails_source_size_required(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.buffer_size = 4,
	});

	assert(riter_error(&riter) == RITER_ERROR_SOURCE_SIZE_REQUIRED);

	riter_deinit(&riter);
}

static void test_init_fails_buffer_size_required(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
	});

	assert(riter_error(&riter) == RITER_ERROR_BUFFER_SIZE_REQUIRED);

	riter_deinit(&riter);
}

static void test_init_fails_data_size_larger_than_buffer_size(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 1,
		.data_size = 2,
	});

	assert(riter_error(&riter) == RITER_ERROR_DATA_SIZE_LARGER_THAN_BUFFER_SIZE);

	riter_deinit(&riter);
}

int main(void)
{
	test_init_fails_source_required();
	test_init_fails_source_size_required();
	test_init_fails_buffer_size_required();
	test_init_fails_data_size_larger_than_buffer_size();
}

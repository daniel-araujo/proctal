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

static void test_default_align_is_1(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
	});

	assert(riter_data_align(&riter) == 1);

	riter_deinit(&riter);
}

static void test_default_size_is_1(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 4,
	});

	assert(riter_data_size(&riter) == 1);

	riter_deinit(&riter);
}

int main(void)
{
	test_default_align_is_1();
	test_default_size_is_1();
}

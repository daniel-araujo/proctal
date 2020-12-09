#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "riter/riter.h"

/*
 * Region of memory that is going to be iterated over.
 */
char memory[] = {
	1, 2, 3, 4,
};

static void test_end_is_reported_when_next_read_signals_end(void)
{
	struct riter riter;

	riter_init(&riter, &(struct riter_config) {
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 2,
		.data_align = 2,
		.data_size = 2,
	});

	assert(riter_next(&riter));
	assert(riter_next(&riter) == 0);
	assert(riter_end(&riter));

	riter_deinit(&riter);
}

int main(void)
{
	test_end_is_reported_when_next_read_signals_end();
	//test_end_is_reported_when_next_read_signals_end_without_reaching_the_end_of_chunk();
}

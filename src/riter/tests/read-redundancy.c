#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "src/riter/riter.h"

/*
 * Region of memory that is going to be iterated over.
 */
char memory[] = { 0, 0, 0, 0 };

struct user {
	int called;
};

static int reader_counter(void *user, void *src, void *out, size_t size)
{
	struct user *real_user = user;

	real_user->called += 1;

	return memcpy(out, src, size) != NULL;
}

static void test_should_not_read_first_if_empty(void)
{
	struct riter riter;
	struct user user = {};

	riter_init(&riter, &(struct riter_config) {
		.reader = reader_counter,
		.source = memory,
		.source_size = 0,
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
		.user = &user,
	});

	assert(user.called == 0);

	riter_deinit(&riter);
}

static void test_should_not_read_first_if_not_enough_data(void)
{
	struct riter riter;
	struct user user = {};

	riter_init(&riter, &(struct riter_config) {
		.reader = reader_counter,
		.source = memory,
		.source_size = 1,
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
		.user = &user,
	});

	assert(user.called == 0);

	riter_deinit(&riter);
}

static void test_should_not_read_last_if_not_enough_data(void)
{
	struct riter riter;
	struct user user = {};

	riter_init(&riter, &(struct riter_config) {
		.reader = reader_counter,
		.source = memory,
		.source_size = 3,
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
		.user = &user,
	});

	assert(riter_next(&riter));
	assert(riter_next(&riter) == 0);
	assert(user.called == 2);

	riter_deinit(&riter);
}

int main(void)
{
	test_should_not_read_first_if_empty();
	test_should_not_read_first_if_not_enough_data();
	test_should_not_read_last_if_not_enough_data();
}

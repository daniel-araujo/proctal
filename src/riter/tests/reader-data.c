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

static int reader_always_fails(void *user, void *src, void *out, size_t size)
{
	struct user *real_user = user;

	real_user->called++;

	return 0;
}

static void test_passes_user_in_init(void)
{
	struct riter riter;
	struct user user = {};

	riter_init(&riter, &(struct riter_config) {
		.reader = reader_always_fails,
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
		.user = &user,
	});
	
	assert(user.called == 1);
}

static void test_passes_user_in_next(void)
{
	struct riter riter;
	struct user user = {};

	riter_init(&riter, &(struct riter_config) {
		.reader = reader_always_fails,
		.source = memory,
		.source_size = sizeof(memory),
		.buffer_size = 2,
		.data_align = 1,
		.data_size = 2,
		.user = &user,
	});

	riter_next(&riter);
	
	assert(user.called == 2);
}

int main(void)
{
	test_passes_user_in_init();
	test_passes_user_in_next();
}

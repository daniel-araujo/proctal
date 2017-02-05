#include <stdio.h>

#include "swbuf/swbuf.h"

static void *malloc_fail(size_t size)
{
	return NULL;
}

static void fake_free(void *b)
{
}

/*
 * Checks if swbuf_error reports an error when swbuf_init fails because
 * the allocator failed to return a valid pointer.
 */
int main(void)
{
	swbuf_set_malloc(malloc_fail);
	swbuf_set_free(fake_free);

	struct swbuf buf;
	swbuf_init(&buf, 200);

	if (swbuf_error(&buf) != 1) {
		fprintf(stderr, "swbuf_error didn't report an error.\n");
		swbuf_deinit(&buf);
		return 1;
	}

	return 0;
}

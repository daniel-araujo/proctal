#include <stdio.h>

#include "swbuf/swbuf.h"

static void *malloc_succeed(size_t size)
{
	static char block[1024];

	if (size < sizeof(block)) {
		return block;
	}

	return NULL;
}

static void fake_free(void *b)
{
}

/*
 * Checks if swbuf_error reports no errors if swbuf_init succeeds.
 */
int main(void)
{
	swbuf_malloc_set(malloc_succeed);
	swbuf_free_set(fake_free);

	struct swbuf buf;
	swbuf_init(&buf, 200);

	if (swbuf_error(&buf) != 0) {
		fprintf(stderr, "swbuf_error reported an error.\n");
		swbuf_deinit(&buf);
		return 1;
	}

	swbuf_deinit(&buf);
	return 0;
}

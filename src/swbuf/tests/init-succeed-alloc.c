#include <stdio.h>
#include <assert.h>

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

	assert(swbuf_error(&buf) == 0);

	swbuf_deinit(&buf);
}

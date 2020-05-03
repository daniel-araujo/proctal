#include <stdio.h>
#include <assert.h>

#include "swbuf/swbuf.h"

static void *malloc_fail(size_t size)
{
	return NULL;
}

static void free_fail(void *b)
{
	fprintf(stderr, "Should not free something that was never allocated.\n");
	abort();
}

int main(void)
{
	swbuf_malloc_set(malloc_fail);
	swbuf_free_set(free_fail);

	struct swbuf buf;
	swbuf_init(&buf, 1);

	assert(swbuf_error(&buf));

	swbuf_deinit(&buf);
}

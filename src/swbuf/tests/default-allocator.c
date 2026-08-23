#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "swbuf/swbuf.h"

/*
 * Checks that swbuf works with the real malloc/free when no custom
 * allocator has been registered.
 */
int main(void)
{
	struct swbuf buf;
	swbuf_init(&buf, 64);

	assert(swbuf_error(&buf) == 0);

	memset(swbuf_offset(&buf, 0), 0x42, swbuf_size(&buf));

	unsigned char *ptr = swbuf_offset(&buf, 0);

	for (size_t i = 0; i < swbuf_size(&buf); i++) {
		assert(ptr[i] == 0x42);
	}

	swbuf_deinit(&buf);
}

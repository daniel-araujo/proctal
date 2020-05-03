#include <stdio.h>
#include <assert.h>

#include "swbuf/swbuf.h"

int main(void)
{
	struct swbuf buf;
	swbuf_init(&buf, 20);

	assert(swbuf_size(&buf) == 20);

	swbuf_swap(&buf);

	// Shouldn't change because of a swap.
	assert(swbuf_size(&buf) == 20);

	swbuf_swap(&buf);

	// Back to the initial state.
	assert(swbuf_size(&buf) == 20);

	swbuf_deinit(&buf);
}

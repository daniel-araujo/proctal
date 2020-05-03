#include <stdio.h>
#include <assert.h>

#include "swbuf/swbuf.h"

int main(void)
{
	struct swbuf buf;
	swbuf_init(&buf, 1);

	char *start_addr = swbuf_offset(&buf, 0);
	char *next_addr = swbuf_offset(&buf, 1);
	char *prev_addr = swbuf_offset(&buf, -1);

	assert(start_addr + 1 == next_addr);
	assert(start_addr - 1 == prev_addr);

	swbuf_deinit(&buf);
}

#include <stdio.h>

#include "swbuf/swbuf.h"

int main(void)
{
	struct swbuf buf;
	swbuf_init(&buf, 20);

	if (swbuf_size(&buf) != 20) {
		fprintf(stderr, "swbuf_size did not report the same size given to swbuf_init.\n");
		swbuf_deinit(&buf);
		return 1;
	}

	swbuf_swap(&buf);

	if (swbuf_size(&buf) != 20) {
		fprintf(stderr, "After a swap swbuf_size did not report the same size given to swbuf_init.\n");
		swbuf_deinit(&buf);
		return 1;
	}

	swbuf_deinit(&buf);
	return 0;
}

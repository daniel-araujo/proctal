#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "swbuf/swbuf.h"

#define BUF_SIZE 2

int main(void)
{
	struct swbuf buf;
	swbuf_init(&buf, BUF_SIZE);

	// One side has 0s
	memset(swbuf_offset(&buf, 0), 0x00, BUF_SIZE);

	// The other has 1s
	memset(swbuf_offset(&buf, -BUF_SIZE), 0xFF, BUF_SIZE);

	swbuf_swap(&buf);

	for (int i = 0; i < BUF_SIZE; i++) {
		unsigned char *ptr = swbuf_offset(&buf, i);

		if (*ptr != 0xFF) {
			fprintf(stderr, "Offset %i does not equal 0xFF.", i);
			abort();
		}
	}

	for (int i = -BUF_SIZE; i < 0; i++) {
		unsigned char *ptr = swbuf_offset(&buf, i);

		if (*ptr != 0x00) {
			fprintf(stderr, "Offset %i does not equal 0x00.", i);
			abort();
		}
	}

	swbuf_deinit(&buf);
}

#include <stdio.h>

#include "swbuf/swbuf.h"

int main(void)
{
	struct swbuf buf;
	swbuf_init(&buf, 20);

	char *start_addr = swbuf_address_offset(&buf, 0);
	char *next_addr = swbuf_address_offset(&buf, 1);

	if (start_addr + 1 != next_addr) {
		fprintf(stderr, "Was expecting swbuf_address_offset(&buf, 0) + 1 to be equal to swbuf_address_offset(&buf, 1).\n");
		swbuf_deinit(&buf);
		return 1;
	}

	swbuf_swap(&buf);

	char *swapped_start_addr = swbuf_address_offset(&buf, -20);

	if (swapped_start_addr != start_addr) {
		fprintf(stderr, "Was expecting swbuf_address_offset(&buf, 0) to be equal to swbuf_address_offset(&buf, -20) after a swap.\n");
		swbuf_deinit(&buf);
		return 1;
	}

	swbuf_deinit(&buf);
	return 0;
}

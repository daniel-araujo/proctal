#include <stdio.h>

#include "swbuf/swbuf.h"

int main(void)
{
	struct swbuf buf;
	swbuf_init(&buf, 20);

	void *original_addr = swbuf_address_offset(&buf, 0);

	swbuf_swap(&buf);

	void *other_side_addr = swbuf_address_offset(&buf, 0);

	if (other_side_addr == original_addr) {
		fprintf(stderr, "swbuf_address_offset returned the same address after a swap. This is not supposed to happen.\n");
		swbuf_deinit(&buf);
		return 1;
	}

	swbuf_swap(&buf);

	void *should_be_original_addr = swbuf_address_offset(&buf, 0);

	if (should_be_original_addr != original_addr) {
		fprintf(stderr, "swbuf_address_offset did not return the same address on the second swap.\n");
		fprintf(stderr, "Was expecting %p, got %p instead.\n", original_addr, should_be_original_addr);
		swbuf_deinit(&buf);
		return 1;
	}

	swbuf_deinit(&buf);
	return 0;
}

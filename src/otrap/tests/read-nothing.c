#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "otrap/otrap.h"

static void test_after_init(void)
{
	struct otrap trap;
	otrap_init(&trap);

	char read_back[4];
	size_t read_size = otrap_read(&trap, read_back, 4);

	if (read_size != 0)  {
		fprintf(stderr, "There should be nothing to read after just having initialized.\n");
		otrap_deinit(&trap);
		exit(1);
	}

	otrap_deinit(&trap);
}

static void test_after_reading_everything(void)
{
	struct otrap trap;
	otrap_init(&trap);

	FILE *f = otrap_file(&trap);

	char output[] = "test";
	size_t output_size = sizeof(output);

	fputs(output, f);

	char read_to_discard[output_size];
	otrap_read(&trap, read_to_discard, output_size);

	char buf[1];
	size_t read_size = otrap_read(&trap, buf, 1);

	if (read_size != 0)  {
		fprintf(stderr, "There should be nothing else to read after reading everything.\n");
		otrap_deinit(&trap);
		exit(1);
	}

	otrap_deinit(&trap);
}

/*
 * Test cases where there should be nothing to read.
 */
int main(void)
{
	test_after_init();
	test_after_reading_everything();
	return 0;
}

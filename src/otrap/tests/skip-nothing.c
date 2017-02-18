#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "otrap/otrap.h"

static void test_after_init(void)
{
	struct otrap trap;
	otrap_init(&trap);

	size_t skip_size = otrap_skip(&trap, 1);

	if (skip_size != 0)  {
		fprintf(stderr, "There should be nothing to skip after just having initialized.\n");
		otrap_deinit(&trap);
		exit(1);
	}

	otrap_deinit(&trap);
}

static void test_after_skipping_everything(void)
{
	struct otrap trap;
	otrap_init(&trap);

	FILE *f = otrap_file(&trap);

	char output[] = "test";
	size_t output_size = sizeof(output);

	fputs(output, f);

	otrap_skip(&trap, output_size);
	size_t skip_size = otrap_skip(&trap, 1);

	if (skip_size != 0)  {
		fprintf(stderr, "There should be nothing else to skip after skipping everything.\n");
		otrap_deinit(&trap);
		exit(1);
	}

	otrap_deinit(&trap);
}

/*
 * Test cases where there should be nothing to skip.
 */
int main(void)
{
	test_after_init();
	test_after_skipping_everything();
	return 0;
}

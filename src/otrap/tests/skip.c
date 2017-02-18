#include <stdio.h>
#include <string.h>

#include "otrap/otrap.h"

int main(void)
{
	struct otrap trap;
	otrap_init(&trap);

	FILE *f = otrap_file(&trap);

	char output[] = "test";
	size_t output_size = sizeof(output) - 1;

	fputs(output, f);

	size_t skipped = otrap_skip(&trap, output_size);

	if (skipped != output_size)  {
		fprintf(stderr, "Did not skip the correct number of characters.\n");
		fprintf(stderr, "Expected to skip %d but was actually %d.\n", (int) output_size, (int) skipped);
		otrap_deinit(&trap);
		return 1;
	}

	otrap_deinit(&trap);
	return 0;
}

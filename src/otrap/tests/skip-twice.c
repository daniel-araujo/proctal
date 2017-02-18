#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "otrap/otrap.h"

static void skip(struct otrap *trap, const char *output)
{
	static int call = 0;
	++call;

	FILE *f = otrap_file(trap);

	size_t output_size = strlen(output);

	fputs(output, f);

	size_t skipped = otrap_skip(trap, output_size);

	if (skipped != output_size)  {
		fprintf(stderr, "Did not skip the right number of characters on the #%d call.\n", call);
		otrap_deinit(trap);
		exit(1);
	}
}

int main(void)
{
	struct otrap trap;
	otrap_init(&trap);

	skip(&trap, "test1");
	skip(&trap, "test2asdf");

	otrap_deinit(&trap);
	return 0;
}

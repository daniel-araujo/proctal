#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "otrap/otrap.h"

static void read(struct otrap *trap, const char *output)
{
	static int call = 0;
	++call;

	FILE *f = otrap_file(trap);

	size_t output_size = strlen(output);

	fputs(output, f);

	char trapped[output_size];

	size_t read_size = otrap_read(trap, trapped, output_size);

	if (read_size != output_size
		|| memcmp(output, trapped, read_size) != 0)  {
		fprintf(stderr, "Output read back is different on #%d call.\n", call);
		otrap_deinit(trap);
		exit(1);
	}
}

int main(void)
{
	struct otrap trap;
	otrap_init(&trap);

	read(&trap, "test1");
	read(&trap, "test2asdf");

	otrap_deinit(&trap);
	return 0;
}

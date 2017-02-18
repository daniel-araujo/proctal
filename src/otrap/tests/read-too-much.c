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

	size_t extra_size = 3;

	size_t read_back_size = output_size + extra_size;
	char read_back[read_back_size];

	size_t read_size = otrap_read(&trap, read_back, read_back_size);

	if (read_size != read_back_size - extra_size)  {
		fprintf(stderr, "Was only supposed to read back as much as was written.\n");
		otrap_deinit(&trap);
		return 1;
	}

	otrap_deinit(&trap);
	return 0;
}

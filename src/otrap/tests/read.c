#include <stdio.h>
#include <string.h>

#include "otrap/otrap.h"

int main(void)
{
	struct otrap trap;
	otrap_init(&trap);

	FILE *f = otrap_file(&trap);

	char expected[] = "test";
	size_t expected_size = sizeof(expected) - 1;

	fputs(expected, f);

	char trapped[expected_size];
	size_t trapped_size = sizeof(trapped);

	size_t read = otrap_read(&trap, trapped, trapped_size);

	if (read != expected_size
		|| memcmp(expected, trapped, read) != 0)  {
		fprintf(stderr, "Output read back is different.\n");
		fprintf(stderr, "Expected (size: %d): ", (int) expected_size);
		fwrite(expected, expected_size, 1, stderr);
		fputs("\n", stderr);
		fprintf(stderr, "Read back (size: %d): ", (int) read);
		fwrite(trapped, read > trapped_size ? trapped_size : read, 1, stderr);
		fputs("\n", stderr);

		otrap_deinit(&trap);
		return 1;
	}

	otrap_deinit(&trap);
	return 0;
}

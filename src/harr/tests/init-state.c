#include <stdio.h>

#include "harr/harr.h"

int main(void)
{
	struct harr array;
	harr_init(&array, sizeof(int));

	if (harr_size(&array) != 0) {
		fprintf(stderr, "Was expecting array to start out empty (0 size).\n");
		harr_deinit(&array);
		return 1;
	}

	harr_deinit(&array);
	return 0;
}

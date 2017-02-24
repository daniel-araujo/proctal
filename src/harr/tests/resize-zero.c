#include <stdio.h>

#include "harr/harr.h"

int main(void)
{
	struct harr array;
	harr_init(&array, sizeof(int));
	harr_resize(&array, 2);
	harr_resize(&array, 0);

	if (harr_size(&array) != 0) {
		fprintf(stderr, "Was expecting size to be 0.\n");
		harr_deinit(&array);
		return 1;
	}

	harr_deinit(&array);
	return 0;
}

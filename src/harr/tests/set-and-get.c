#include <stdio.h>

#include "harr/harr.h"

int main(void)
{
	int expected_value = 123456789;
	int retrieved_value = 0;

	struct harr array;
	harr_init(&array, sizeof(int));
	harr_resize(&array, 1);
	harr_set(&array, 0, &expected_value);
	harr_get(&array, 0, &retrieved_value);

	if (retrieved_value != expected_value) {
		fprintf(stderr, "Failed to either set or get the expected value.\n");
		harr_deinit(&array);
		return 1;
	}

	harr_deinit(&array);
	return 0;
}

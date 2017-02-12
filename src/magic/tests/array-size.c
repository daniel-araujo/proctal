#include <stdlib.h>
#include <stdio.h>

#include "magic/magic.h"

struct mixed {
	char a;
	int b;
};

int main(void)
{
#define CHECK(ARRAY, EXPECTED_ITEM_SIZE, ITEM_SIZE) \
	do { \
		size_t item_size = ITEM_SIZE; \
		size_t expected_item_size = EXPECTED_ITEM_SIZE; \
\
		if (item_size != expected_item_size) { \
			fprintf(stderr, "Wrong size for '" #ARRAY "' array.\n"); \
			fprintf(stderr, "Expected %lu but got %lu\n", expected_item_size, item_size); \
			return 1; \
		} \
	} while (0);

	char chars[20];
	int ints[20];
	int *pointers[20];
	struct mixed mixed[20];

	// Where each element is exactly 1 character in size.
	CHECK(chars, 20, ARRAY_SIZE(chars));

	// Where each element is more than 1 character in size.
	CHECK(ints, 20, ARRAY_SIZE(ints));

	// Where each element is a pointer.
	CHECK(pointers, 20, ARRAY_SIZE(pointers));

	// Where each element is a struct with members of different sizes.
	CHECK(mixed, 20, ARRAY_SIZE(mixed));

	return 0;

#undef CHECK
}

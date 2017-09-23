#include <stdlib.h>
#include <stdio.h>

#include "magic/magic.h"

int main(void)
{
#define CHECK(W, X, Y, Z) \
	do { \
		int result = W(X, Y); \
\
		if (result != Z) { \
			fprintf(stderr, #W "(" #X ", " #Y") resulted in %d but was expecting " #Z ".\n", result); \
			return 1; \
		} \
	} while (0);

	// Using plain integers.
	CHECK(COMPARE_INT, 0, 0, 0);
	CHECK(COMPARE_INT, 1, 2, -1);
	CHECK(COMPARE_INT, 1, 1, 0);
	CHECK(COMPARE_INT, 2, 1, 1);

	// Long ints.
	CHECK(COMPARE_INT, 0U, 0U, 0);
	CHECK(COMPARE_INT, 1U, 2U, -1);
	CHECK(COMPARE_INT, 1U, 1U, 0);
	CHECK(COMPARE_INT, 2U, 1U, 1);

	// Floats.
	CHECK(COMPARE_FLOAT, 0, 0, 0);
	CHECK(COMPARE_FLOAT, 1.0, 2.0, -1);
	CHECK(COMPARE_FLOAT, 1.0, 1.0, 0);
	CHECK(COMPARE_FLOAT, 2.0, 1.0, 1);
	CHECK(COMPARE_FLOAT, 0.1, 0.2, -1);
	CHECK(COMPARE_FLOAT, 0.2, 0.1, 1);

	return 0;

#undef CHECK
}

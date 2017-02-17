#include <stdlib.h>
#include <stdio.h>

#include "cli/val/integer.h"
#include "magic/magic.h"

int main(void)
{
	struct test {
		int8_t value1;
		int8_t value2;
		int expected;
	};

	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_set_sign(&a, CLI_VAL_INTEGER_SIGN_2SCMPL);
	cli_val_integer_attr_set_size(&a, CLI_VAL_INTEGER_SIZE_8);

	struct test tests[] = {
		{
			.value1 = 1,
			.value2 = 2,
			.expected = -1,
		},
		{
			.value1 = 1,
			.value2 = 1,
			.expected = 0,
		},
		{
			.value1 = 0,
			.value2 = 0,
			.expected = 0,
		},
		{
			.value1 = 1,
			.value2 = 0,
			.expected = 1,
		},
		{
			.value1 = 0,
			.value2 = 1,
			.expected = -1,
		},
		{
			.value1 = -1,
			.value2 = -1,
			.expected = 0,
		},
		{
			.value1 = -1,
			.value2 = 0,
			.expected = -1,
		},
		{
			.value1 = -1,
			.value2 = -2,
			.expected = 1,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
		struct test *test = &tests[i];

		struct cli_val_integer *v1 = cli_val_integer_create(&a);
		cli_val_integer_parse_bin(v1, (const char *) &test->value1, sizeof(test->value2));

		struct cli_val_integer *v2 = cli_val_integer_create(&a);
		cli_val_integer_parse_bin(v2, (const char *) &test->value2, sizeof(test->value2));

		int r = cli_val_integer_cmp(v1, v2);

		if (r != test->expected) {
			fprintf(stderr, "Comparing %d and %d resulted in %d but was expecting %d instead.\n", test->value1, test->value2, r, test->expected);
			cli_val_integer_destroy(v2);
			cli_val_integer_destroy(v1);
			cli_val_integer_attr_deinit(&a);
			return 1;
		}

		cli_val_integer_destroy(v2);
		cli_val_integer_destroy(v1);
	}

	cli_val_integer_attr_deinit(&a);

	return 0;
}

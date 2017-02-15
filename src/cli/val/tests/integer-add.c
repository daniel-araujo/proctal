#include <stdlib.h>
#include <stdio.h>

#include "cli/val/integer.h"
#include "magic/magic.h"

int main(void)
{
	struct test {
		int8_t value1;
		int8_t value2;
		int8_t expected;
	};

	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_set_sign(&a, CLI_VAL_INTEGER_SIGN_2SCMPL);
	cli_val_integer_attr_set_size(&a, CLI_VAL_INTEGER_SIZE_8);

	struct test tests[] = {
		{
			.value1 = 1,
			.value2 = 1,
			.expected = 2,
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
			.expected = 1,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
		struct test *test = &tests[i];

		struct cli_val_integer *v1 = cli_val_integer_create(&a);
		cli_val_integer_parse_bin(v1, &test->value1, sizeof(test->value2));

		struct cli_val_integer *v2 = cli_val_integer_create(&a);
		cli_val_integer_parse_bin(v2, &test->value2, sizeof(test->value2));

		cli_val_integer_add(v1, v2, v1);

		int8_t *r = cli_val_integer_raw(v1);

		if (*r != test->expected) {
			fprintf(stderr, "Expected %d + %d to equal %d but got ", test->value1, test->value2, test->expected);
			cli_val_integer_print(v1, stderr);
			fprintf(stderr, " instead.\n");
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

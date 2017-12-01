#include <stdlib.h>
#include <stdio.h>

#include "cli/val.h"
#include "cli/val/filter.h"

struct test {
	const char *value;

	const char *eq;
	const char *ne;
	const char *gt;
	const char *gte;
	const char *lt;
	const char *lte;

	int result;
};

static struct cli_val_filter_compare_arg *create_filter_arg(struct test *test, cli_val_t v)
{
	struct cli_val_filter_compare_arg *arg = malloc(sizeof(*arg));

	cli_val_t nil = cli_val_nil();

#define CREATE(NAME) \
	if (test->NAME != NULL) { \
		arg->NAME = cli_val_create_clone(v); \
		cli_val_parse_text(arg->NAME, test->NAME); \
	} else { \
		arg->NAME = nil; \
	}

	CREATE(eq);
	CREATE(ne);
	CREATE(gt);
	CREATE(gte);
	CREATE(lt);
	CREATE(lte);

#undef CREATE

	return arg;
}

static void destroy_filter_arg(struct cli_val_filter_compare_arg *arg)
{
	free(arg);
}

int main(void)
{
	struct test tests[] = {
		// Equals
		{
			.value = "1",
			.eq = "1",
			.result = 1,
		},
		{
			.value = "1",
			.eq = "2",
			.result = 0,
		},

		// Not equals.
		{
			.value = "2",
			.ne = "1",
			.result = 1,
		},
		{
			.value = "2",
			.ne = "2",
			.result = 0,
		},

		// Greater than.
		{
			.value = "1",
			.gt = "0",
			.result = 1,
		},
		{
			.value = "1",
			.gt = "1",
			.result = 0,
		},

		// Greater or equal than.
		{
			.value = "1",
			.gte = "0",
			.result = 1,
		},
		{
			.value = "1",
			.gte = "1",
			.result = 1,
		},

		// Less than.
		{
			.value = "1",
			.lt = "2",
			.result = 1,
		},
		{
			.value = "1",
			.lt = "1",
			.result = 0,
		},

		// Less or equal than.
		{
			.value = "1",
			.lte = "2",
			.result = 1,
		},
		{
			.value = "1",
			.lte = "1",
			.result = 1,
		},
	};

	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT);
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_8);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
		struct test *test = &tests[i];

		cli_val_parse_text(v, test->value);

		struct cli_val_filter_compare_arg *filter_arg = create_filter_arg(test, v);

		if (cli_val_filter_compare(filter_arg, v) != test->result) {
			printf("Test %d failed.\n", (int) i);
			destroy_filter_arg(filter_arg);
			cli_val_destroy(v);
			return 1;
		}

		destroy_filter_arg(filter_arg);
	}

	cli_val_destroy(v);
	return 0;
}

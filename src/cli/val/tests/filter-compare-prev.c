#include <stdlib.h>
#include <stdio.h>

#include "cli/val.h"
#include "cli/val/filter.h"

struct test {
	const char *curr;
	const char *prev;

	int changed;
	int unchanged;
	int increased;
	int decreased;
	const char *inc;
	const char *inc_up_to;
	const char *dec;
	const char *dec_up_to;

	int result;
};

static struct cli_val_filter_compare_prev_arg *create_filter_arg(struct test *test, cli_val v)
{
	struct cli_val_filter_compare_prev_arg *arg = malloc(sizeof(*arg));

	cli_val nil = cli_val_nil();

#define CREATE(NAME) \
	if (test->NAME != NULL) { \
		arg->NAME = cli_val_create_clone(v); \
		cli_val_parse_text(arg->NAME, test->NAME); \
	} else { \
		arg->NAME = nil; \
	}

	CREATE(inc);
	CREATE(inc_up_to);
	CREATE(dec);
	CREATE(dec_up_to);

#undef CREATE

	arg->changed = test->changed;
	arg->unchanged = test->unchanged;
	arg->increased = test->increased;
	arg->decreased = test->decreased;

	return arg;
}

static void destroy_filter_arg(struct cli_val_filter_compare_prev_arg *arg)
{
	free(arg);
}

int main(void)
{
	struct test tests[] = {
		// Changed.
		{
			.curr = "1",
			.prev = "0",
			.changed = 1,
			.result = 1,
		},
		{
			.curr = "1",
			.prev = "1",
			.changed = 1,
			.result = 0,
		},

		// Unchanged.
		{
			.curr = "1",
			.prev = "1",
			.unchanged = 1,
			.result = 1,
		},
		{
			.curr = "1",
			.prev = "0",
			.unchanged = 1,
			.result = 0,
		},

		// Increased.
		{
			.curr = "1",
			.prev = "2",
			.increased = 1,
			.result = 0,
		},
		{
			.curr = "1",
			.prev = "0",
			.increased = 1,
			.result = 1,
		},
		{
			.curr = "1",
			.prev = "1",
			.increased = 1,
			.result = 0,
		},

		// Decreased.
		{
			.curr = "1",
			.prev = "2",
			.decreased = 1,
			.result = 1,
		},
		{
			.curr = "1",
			.prev = "1",
			.decreased = 1,
			.result = 0,
		},
		{
			.curr = "1",
			.prev = "0",
			.decreased = 1,
			.result = 0,
		},

		// Incremented.
		{
			.curr = "2",
			.prev = "1",
			.inc = "1",
			.result = 1,
		},
		{
			.curr = "1",
			.prev = "1",
			.inc = "1",
			.result = 0,
		},
		{
			.curr = "2",
			.prev = "1",
			.inc = "2",
			.result = 0,
		},

		// Incremented up to.
		{
			.curr = "2",
			.prev = "1",
			.inc_up_to = "3",
			.result = 1,
		},
		{
			.curr = "4",
			.prev = "1",
			.inc_up_to = "3",
			.result = 1,
		},
		{
			.curr = "5",
			.prev = "1",
			.inc_up_to = "3",
			.result = 0,
		},

		// Decremented.
		{
			.curr = "2",
			.prev = "3",
			.dec = "1",
			.result = 1,
		},
		{
			.curr = "1",
			.prev = "1",
			.dec = "1",
			.result = 0,
		},
		{
			.curr = "2",
			.prev = "3",
			.dec = "2",
			.result = 0,
		},

		// Decremented up to.
		{
			.curr = "3",
			.prev = "4",
			.dec_up_to = "3",
			.result = 1,
		},
		{
			.curr = "1",
			.prev = "4",
			.dec_up_to = "3",
			.result = 1,
		},
		{
			.curr = "0",
			.prev = "4",
			.dec_up_to = "3",
			.result = 0,
		},
	};

	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT);
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_8);
	cli_val vcurr = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);
	cli_val vprev = cli_val_create_clone(vcurr);

	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
		struct test *test = &tests[i];

		cli_val_parse_text(vcurr, test->curr);
		cli_val_parse_text(vprev, test->prev);

		struct cli_val_filter_compare_prev_arg *filter_arg = create_filter_arg(test, vcurr);

		if (cli_val_filter_compare_prev(filter_arg, vcurr, vprev) != test->result) {
			printf("Test %d failed.\n", (int) i);
			destroy_filter_arg(filter_arg);
			cli_val_destroy(vcurr);
			cli_val_destroy(vprev);
			return 1;
		}

		destroy_filter_arg(filter_arg);
	}

	cli_val_destroy(vcurr);
	cli_val_destroy(vprev);
	return 0;
}

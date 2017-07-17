#include <stdlib.h>
#include <stdio.h>

#include "cli/val.h"
#include "magic/magic.h"

struct test {
	const char *value1;
	const char *value2;
	int result;
};

#define COMMON_INT \
	{ \
		.value1 = "1", \
		.value2 = "2", \
		.result = -1, \
	}, \
	{ \
		.value1 = "1", \
		.value2 = "1", \
		.result = 0, \
	}, \
	{ \
		.value1 = "0", \
		.value2 = "0", \
		.result = 0, \
	}, \
	{ \
		.value1 = "1", \
		.value2 = "0", \
		.result = 1, \
	}, \
	{ \
		.value1 = "0", \
		.value2 = "1", \
		.result = -1, \
	}

#define COMMON_INT_SIGN \
	{ \
		.value1 = "-1", \
		.value2 = "-1", \
		.result = 0, \
	}, \
	{ \
		.value1 = "-1", \
		.value2 = "0", \
		.result = -1, \
	}, \
	{ \
		.value1 = "-1", \
		.value2 = "-2", \
		.result = 1, \
	}

#define COMMON_DECIMAL \
	{ \
		.value1 = "1.2", \
		.value2 = "1", \
		.result = 1, \
	}, \
	{ \
		.value1 = "1", \
		.value2 = "1.2", \
		.result = -1, \
	}

#define COMMON_DECIMAL_SIGN \
	{ \
		.value1 = "-1.2", \
		.value2 = "1", \
		.result = -1, \
	}

#define COMMON_ASCII \
	{ \
		.value1 = "A", \
		.value2 = "A", \
		.result = 0, \
	}, \
	{ \
		.value1 = "A", \
		.value2 = "a", \
		.result = -1, \
	} \

static int run(const char *name, struct test *tests, size_t size, cli_val v)
{
	for (size_t i = 0; i < size; ++i) {
		struct test *test = &tests[i];

		cli_val v1 = cli_val_create_clone(v);
		cli_val_parse(v1, test->value1);

		cli_val v2 = cli_val_create_clone(v);
		cli_val_parse(v2, test->value2);

		int r = cli_val_cmp(v1, v2);

		if (r != test->result) {
			fprintf(stderr, "%s: Comparing %s and %s resulted in %d but was expecting %d instead.\n", name, test->value1, test->value2, r, test->result);
			cli_val_destroy(v2);
			cli_val_destroy(v1);
			return 1;
		}

		cli_val_destroy(v2);
		cli_val_destroy(v1);
	}

	return 0;
}

static void test_byte()
{
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_BYTE, cli_val_byte_create());

	struct test tests[] = {
		{
			.value1 = "00",
			.value2 = "00",
			.result = 0,
		},
		{
			.value1 = "02",
			.value2 = "01",
			.result = 1,
		},
		{
			.value1 = "0A",
			.value2 = "01",
			.result = 1,
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_integer_8_twos_complement()
{
	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_8);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
		COMMON_INT_SIGN,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_integer_8_unsigned()
{
	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_UNSIGNED);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_8);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_integer_16_twos_complement()
{
	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_16);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
		COMMON_INT_SIGN,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_integer_16_unsigned()
{
	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_UNSIGNED);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_16);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_integer_32_twos_complement()
{
	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_32);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
		COMMON_INT_SIGN,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_integer_32_unsigned()
{
	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_UNSIGNED);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_32);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_integer_64_twos_complement()
{
	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_64);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
		COMMON_INT_SIGN,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_integer_64_unsigned()
{
	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_sign_set(&a, CLI_VAL_INTEGER_SIGN_UNSIGNED);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_64);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
	cli_val_integer_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_ieee754_single()
{
	struct cli_val_ieee754_attr a;
	cli_val_ieee754_attr_init(&a);
	cli_val_ieee754_attr_precision_set(&a, CLI_VAL_IEEE754_PRECISION_SINGLE);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_IEEE754, cli_val_ieee754_create(&a));
	cli_val_ieee754_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
		COMMON_DECIMAL,
		COMMON_DECIMAL_SIGN,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_ieee754_double()
{
	struct cli_val_ieee754_attr a;
	cli_val_ieee754_attr_init(&a);
	cli_val_ieee754_attr_precision_set(&a, CLI_VAL_IEEE754_PRECISION_DOUBLE);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_IEEE754, cli_val_ieee754_create(&a));
	cli_val_ieee754_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
		COMMON_DECIMAL,
		COMMON_DECIMAL_SIGN,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_ieee754_extended()
{
	struct cli_val_ieee754_attr a;
	cli_val_ieee754_attr_init(&a);
	cli_val_ieee754_attr_precision_set(&a, CLI_VAL_IEEE754_PRECISION_EXTENDED);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_IEEE754, cli_val_ieee754_create(&a));
	cli_val_ieee754_attr_deinit(&a);

	struct test tests[] = {
		COMMON_INT,
		COMMON_DECIMAL,
		COMMON_DECIMAL_SIGN,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_text_ascii()
{
	struct cli_val_text_attr a;
	cli_val_text_attr_init(&a);
	cli_val_text_attr_charset_set(&a, CLI_VAL_TEXT_CHARSET_ASCII);
	cli_val v = cli_val_wrap(CLI_VAL_TYPE_TEXT, cli_val_text_create(&a));
	cli_val_text_attr_deinit(&a);

	struct test tests[] = {
		COMMON_ASCII,
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

/*
 * Tests all addition operations.
 */
int main(void)
{
	test_byte();

	test_integer_8_twos_complement();
	test_integer_8_unsigned();
	test_integer_16_twos_complement();
	test_integer_16_unsigned();
	test_integer_32_twos_complement();
	test_integer_32_unsigned();
	test_integer_64_twos_complement();
	test_integer_64_unsigned();

	test_ieee754_single();
	test_ieee754_double();
	test_ieee754_extended();

	test_text_ascii();

	return 0;
}

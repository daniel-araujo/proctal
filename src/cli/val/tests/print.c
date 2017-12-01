#include <stdlib.h>
#include <stdio.h>

#include "cli/val.h"
#include "magic/magic.h"
#include "otrap/otrap.h"

struct test {
	const char *value;
};

#define COMMON_INT \
	{ \
		.value = "0", \
	}, \
	{ \
		.value = "1", \
	}

#define COMMON_INT_SIGN \
	{ \
		.value = "-1", \
	}, \
	{ \
		.value = "0", \
	}, \
	{ \
		.value = "-1", \
	}

#define COMMON_DECIMAL \
	{ \
		.value = "1.2", \
	}, \
	{ \
		.value = "0.2", \
	}, \
	{ \
		.value = "0.888888", \
	}, \
	{ \
		.value = "1", \
	}, \
	{ \
		.value = "1", \
	}

#define COMMON_DECIMAL_SIGN \
	{ \
		.value = "-1.2", \
	}

#define COMMON_ASCII \
	{ \
		.value = "A", \
	}, \
	{ \
		.value = "a", \
	} \

static int run(const char *name, struct test *tests, size_t size, cli_val_t v)
{
	for (size_t i = 0; i < size; ++i) {
		struct test *test = &tests[i];

		cli_val_parse_text(v, test->value);

		struct otrap otrap;
		otrap_init(&otrap);

		cli_val_print(v, otrap_file(&otrap));

		char output[255];
		size_t output_size = otrap_read(&otrap, output, sizeof(output));

		size_t expect_size = strlen(test->value);

		if (output_size != expect_size
			|| memcmp(test->value, output, output_size) != 0) {
			fprintf(stderr, "%s: Expected '%s'\n", name, test->value);
			fprintf(stderr, "Got '%.*s' instead.\n", (int) output_size, output);
			otrap_deinit(&otrap);
			return 1;
		}

		otrap_deinit(&otrap);
	}

	return 0;
}

static void test_byte()
{
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_BYTE, cli_val_byte_create());

	struct test tests[] = {
		{
			.value = "00",
		},
		{
			.value = "02",
		},
		{
			.value = "0A",
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
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_8);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
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
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_8);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
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
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_16);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
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
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_16);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
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
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_32);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
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
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_32);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
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
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_64);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
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
	cli_val_integer_attr_bits_set(&a, CLI_VAL_INTEGER_BITS_64);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_INTEGER, cli_val_integer_create(&a));
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
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_IEEE754, cli_val_ieee754_create(&a));
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
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_IEEE754, cli_val_ieee754_create(&a));
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
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_IEEE754, cli_val_ieee754_create(&a));
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
	cli_val_text_attr_encoding_set(&a, CLI_VAL_TEXT_ENCODING_ASCII);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_TEXT, cli_val_text_create(&a));
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

static void test_address()
{
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_ADDRESS, cli_val_address_create());

	struct test tests[] = {
		{
			.value = "DEADBEEF",
		},
		{
			.value = "0",
		}
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_instruction_x86_64()
{
	struct cli_val_x86_attr a;
	cli_val_x86_attr_init(&a);
	cli_val_x86_attr_mode_set(&a, CLI_VAL_X86_MODE_64);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_X86, cli_val_x86_create(&a));
	cli_val_x86_attr_deinit(&a);

	struct test tests[] = {
		// Without operand.
		{
			.value = "nop",
		},
		// With one operand.
		{
			.value = "dec	rax"
		},
		// With two operands.
		{
			.value = "sub	rsp, 8"
		},
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

	test_address();

	test_instruction_x86_64();

	return 0;
}

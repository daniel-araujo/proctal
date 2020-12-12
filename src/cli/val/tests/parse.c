#include <stdlib.h>
#include <stdio.h>

#include "cli/val/val.h"
#include "magic/magic.h"
#include "otrap/otrap.h"

struct test {
	const char *value;
	const char *result;
};

#define COMMON_INT \
	{ \
		.value = "0", \
		.result = "0", \
	}, \
	{ \
		.value = "1", \
		.result = "1", \
	}

#define COMMON_INT_SIGN \
	{ \
		.value = "-1", \
		.result = "-1", \
	}, \
	{ \
		.value = "0", \
		.result = "0", \
	}, \
	{ \
		.value = "-1", \
		.result = "-1", \
	}

#define COMMON_DECIMAL \
	{ \
		.value = "1.2", \
		.result = "1.2", \
	}, \
	{ \
		.value = "0.2", \
		.result = "0.2", \
	}, \
	{ \
		.value = "0.888888", \
		.result = "0.888888", \
	}, \
	{ \
		.value = "1.00000000", \
		.result = "1", \
	}, \
	{ \
		.value = "1", \
		.result = "1", \
	}

#define COMMON_DECIMAL_SIGN \
	{ \
		.value = "-1.2", \
		.result = "-1.2", \
	}

#define COMMON_ASCII \
	{ \
		.value = "A", \
		.result = "A", \
	}, \
	{ \
		.value = "a", \
		.result = "a", \
	} \

static int run_parse_text(const char *name, struct test *test, cli_val_t v)
{
	if (!cli_val_parse_text(v, test->value)) {
		fprintf(stderr, "%s parse: Failed to parse '%s'\n", name, test->value);
		return 1;
	}

	struct otrap otrap;
	otrap_init(&otrap);

	if (cli_val_print(v, otrap_file(&otrap)) == 0) {
		fprintf(stderr, "%s parse: Failed to print '%s'\n", name, test->value);
		return 1;
	}

	char output[255];
	size_t output_size = otrap_read(&otrap, output, sizeof(output));

	size_t expect_size = strlen(test->result);

	if (output_size != expect_size
		|| memcmp(test->result, output, output_size) != 0) {
		fprintf(stderr, "%s parse: Expected '%s' to result in '%s'\n", name, test->value, test->result);
		fprintf(stderr, "Got '%.*s' instead.\n", (int) output_size, output);
		otrap_deinit(&otrap);
		return 1;
	}

	otrap_deinit(&otrap);

	return 0;
}

static int run_parse_binary(const char *name, struct test *test, cli_val_t v)
{
	cli_val_t sv = cli_val_create_clone(v);
	cli_val_parse_text(sv, test->value);

	if (!cli_val_parse_binary(v, cli_val_data(sv), cli_val_sizeof(sv))) {
		fprintf(stderr, "%s parse_binary: Failed to parse '%s'\n", name, test->value);
		cli_val_destroy(sv);
		return 1;
	}

	cli_val_destroy(sv);

	struct otrap otrap;
	otrap_init(&otrap);

	cli_val_print(v, otrap_file(&otrap));

	char output[255];
	size_t output_size = otrap_read(&otrap, output, sizeof(output));

	size_t expect_size = strlen(test->result);

	if (output_size != expect_size
		|| memcmp(test->result, output, output_size) != 0) {
		fprintf(stderr, "%s parse_binary: Expected '%s' to result in '%s'\n", name, test->value, test->result);
		fprintf(stderr, "Got '%.*s' instead.\n", (int) output_size, output);
		otrap_deinit(&otrap);
		return 1;
	}

	otrap_deinit(&otrap);

	return 0;
}

static int run_scan(const char *name, struct test *test, cli_val_t v)
{
	switch (cli_val_type(v)) {
	case CLI_VAL_TYPE_X86:
	case CLI_VAL_TYPE_ARM:
	case CLI_VAL_TYPE_SPARC:
	case CLI_VAL_TYPE_POWERPC:
	case CLI_VAL_TYPE_MIPS:
		// Not supported.
		return 0;

	default:
		break;
	}

	FILE *file = tmpfile();
	fputs(test->value, file);
	fseek(file, 0, SEEK_SET);

	if (!cli_val_scan(v, file)) {
		fprintf(stderr, "%s scan: Failed to read '%s'\n", name, test->value);
		fclose(file);
		return 1;
	}

	struct otrap otrap;
	otrap_init(&otrap);

	cli_val_print(v, otrap_file(&otrap));

	char output[255];
	size_t output_size = otrap_read(&otrap, output, sizeof(output));

	size_t expect_size = strlen(test->result);

	if (output_size != expect_size
		|| memcmp(test->result, output, output_size) != 0) {
		fprintf(stderr, "%s scan: Expected '%s' to result in '%s'\n", name, test->value, test->result);
		fprintf(stderr, "Got '%.*s' instead.\n", (int) output_size, output);
		fclose(file);
		otrap_deinit(&otrap);
		return 1;
	}

	fclose(file);
	otrap_deinit(&otrap);

	return 0;
}

static int run(const char *name, struct test *tests, size_t size, cli_val_t v)
{
	for (size_t i = 0; i < size; ++i) {
		struct test *test = &tests[i];

		if (run_parse_text(name, test, v)) {
			return 1;
		}

		if (run_parse_binary(name, test, v)) {
			return 1;
		}

		if (run_scan(name, test, v)) {
			return 1;
		}
	}

	return 0;
}

static void test_byte()
{
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_BYTE, cli_val_byte_create());

	struct test tests[] = {
		{
			.value = "00",
			.result = "00",
		},
		{
			.value = "02",
			.result = "02",
		},
		{
			.value = "0A",
			.result = "0A",
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
			.result = "DEADBEEF",
		},
		{
			.value = "0",
			.result = "0",
		},
		{
			.value = "00000000000",
			.result = "0",
		}
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_x86_16()
{
	struct cli_val_x86_attr a;
	cli_val_x86_attr_init(&a);
	cli_val_x86_attr_mode_set(&a, CLI_VAL_X86_MODE_32);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_X86, cli_val_x86_create(&a));
	cli_val_x86_attr_deinit(&a);

	struct test tests[] = {
		// Without operand.
		{
			.value = "nop",
			.result = "nop",
		},
		// With one operand.
		{
			.value = "dec	ax",
			.result = "dec	ax",
		},
		// With two operands.
		{
			.value = "sub	sp, 8",
			.result = "sub	sp, 8",
		},
		// Using spaces.
		{
			.value = "sub  sp, 8",
			.result = "sub	sp, 8",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_x86_32()
{
	struct cli_val_x86_attr a;
	cli_val_x86_attr_init(&a);
	cli_val_x86_attr_mode_set(&a, CLI_VAL_X86_MODE_32);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_X86, cli_val_x86_create(&a));
	cli_val_x86_attr_deinit(&a);

	struct test tests[] = {
		// Without operand.
		{
			.value = "nop",
			.result = "nop",
		},
		// With one operand.
		{
			.value = "dec	eax",
			.result = "dec	eax",
		},
		// With two operands.
		{
			.value = "sub	esp, 8",
			.result = "sub	esp, 8",
		},
		// Using spaces.
		{
			.value = "sub  esp, 8",
			.result = "sub	esp, 8",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_x86_64()
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
			.result = "nop",
		},
		// With one operand.
		{
			.value = "dec	rax",
			.result = "dec	rax",
		},
		// With two operands.
		{
			.value = "sub	rsp, 8",
			.result = "sub	rsp, 8",
		},
		// Using spaces.
		{
			.value = "sub  rsp, 8",
			.result = "sub	rsp, 8",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_arm_a32()
{
	struct cli_val_arm_attr a;
	cli_val_arm_attr_init(&a);
	cli_val_arm_attr_mode_set(&a, CLI_VAL_ARM_MODE_A32);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_ARM, cli_val_arm_create(&a));
	cli_val_arm_attr_deinit(&a);

	struct test tests[] = {
		{
			.value = "mov	r0, #1",
			.result = "mov	r0, #1",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_arm_a64()
{
	struct cli_val_arm_attr a;
	cli_val_arm_attr_init(&a);
	cli_val_arm_attr_mode_set(&a, CLI_VAL_ARM_MODE_A64);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_ARM, cli_val_arm_create(&a));
	cli_val_arm_attr_deinit(&a);

	struct test tests[] = {
		{
			.value = "nop",
			.result = "nop",
		},
		{
			.value = "mov	w19, w0",
			.result = "mov	w19, w0",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_sparc_32()
{
	struct cli_val_sparc_attr a;
	cli_val_sparc_attr_init(&a);
	cli_val_sparc_attr_mode_set(&a, CLI_VAL_SPARC_MODE_32);
	cli_val_sparc_attr_endianness_set(&a, CLI_VAL_SPARC_ENDIANNESS_BIG);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_SPARC, cli_val_sparc_create(&a));
	cli_val_sparc_attr_deinit(&a);

	struct test tests[] = {
		{
			.value = "nop",
			.result = "nop",
		},
		{
			.value = "add	%l1, %l2, %l3",
			.result = "add	%l1, %l2, %l3",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_sparc_64()
{
	struct cli_val_sparc_attr a;
	cli_val_sparc_attr_init(&a);
	cli_val_sparc_attr_mode_set(&a, CLI_VAL_SPARC_MODE_64);
	cli_val_sparc_attr_endianness_set(&a, CLI_VAL_SPARC_ENDIANNESS_BIG);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_SPARC, cli_val_sparc_create(&a));
	cli_val_sparc_attr_deinit(&a);

	struct test tests[] = {
		{
			.value = "nop",
			.result = "nop",
		},
		{
			.value = "add	%l1, %l2, %l3",
			.result = "add	%l1, %l2, %l3",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_powerpc_32()
{
	struct cli_val_powerpc_attr a;
	cli_val_powerpc_attr_init(&a);
	cli_val_powerpc_attr_mode_set(&a, CLI_VAL_POWERPC_MODE_32);
	cli_val_powerpc_attr_endianness_set(&a, CLI_VAL_POWERPC_ENDIANNESS_BIG);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_POWERPC, cli_val_powerpc_create(&a));
	cli_val_powerpc_attr_deinit(&a);

	struct test tests[] = {
		{
			.value = "nop",
			.result = "nop",
		},
		{
			.value = "li	0, 3",
			.result = "li	0, 3",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_powerpc_64()
{
	struct cli_val_powerpc_attr a;
	cli_val_powerpc_attr_init(&a);
	cli_val_powerpc_attr_mode_set(&a, CLI_VAL_POWERPC_MODE_64);
	cli_val_powerpc_attr_endianness_set(&a, CLI_VAL_POWERPC_ENDIANNESS_BIG);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_POWERPC, cli_val_powerpc_create(&a));
	cli_val_powerpc_attr_deinit(&a);

	struct test tests[] = {
		{
			.value = "nop",
			.result = "nop",
		},
		{
			.value = "li	0, 3",
			.result = "li	0, 3",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_mips_32()
{
	struct cli_val_mips_attr a;
	cli_val_mips_attr_init(&a);
	cli_val_mips_attr_mode_set(&a, CLI_VAL_MIPS_MODE_32);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_MIPS, cli_val_mips_create(&a));
	cli_val_mips_attr_deinit(&a);

	struct test tests[] = {
		{
			.value = "nop",
			.result = "nop",
		},
		{
			.value = "add	$t1, $t1, $t0",
			.result = "add	$t1, $t1, $t0",
		},
	};

	int ret = run(__FUNCTION__, tests, ARRAY_SIZE(tests), v);

	cli_val_destroy(v);

	if (ret) {
		exit(1);
	}
}

static void test_mips_64()
{
	struct cli_val_mips_attr a;
	cli_val_mips_attr_init(&a);
	cli_val_mips_attr_mode_set(&a, CLI_VAL_MIPS_MODE_64);
	cli_val_t v = cli_val_wrap(CLI_VAL_TYPE_MIPS, cli_val_mips_create(&a));
	cli_val_mips_attr_deinit(&a);

	struct test tests[] = {
		{
			.value = "nop",
			.result = "nop",
		},
		{
			.value = "sll	$at, $at, 0x10",
			.result = "sll	$at, $at, 0x10",
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
	test_address();
	test_byte();
	test_ieee754_double();
	test_ieee754_extended();
	test_ieee754_single();
	test_integer_16_twos_complement();
	test_integer_16_unsigned();
	test_integer_32_twos_complement();
	test_integer_32_unsigned();
	test_integer_64_twos_complement();
	test_integer_64_unsigned();
	test_integer_8_twos_complement();
	test_integer_8_unsigned();
	test_text_ascii();
	test_x86_16();
	test_x86_32();
	test_x86_64();
	test_arm_a32();
	test_arm_a64();
	test_sparc_32();
	test_sparc_64();
	test_powerpc_32();
	test_powerpc_64();
	test_mips_32();
	test_mips_64();

	return 0;
}

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "otrap/otrap.h"
#include "cli/val/integer.h"

static int expect_print(struct cli_val_integer *v, const char *expected)
{
	int ret = 0;

	struct otrap otrap;
	otrap_init(&otrap);

	cli_val_integer_print(v, otrap_file(&otrap));

	char output[255];
	size_t output_size = otrap_read(&otrap, output, sizeof(output));

	if (output_size != strlen(expected)
		|| memcmp(output, expected, output_size) != 0) {
		fprintf(stderr, "Expected %s, but instead got ", expected);
		fwrite(output, output_size, 1, stderr);
		fprintf(stderr, ".\n");
		goto exit1;
	}

	ret = 1;
exit1:
	otrap_deinit(&otrap);
exit0:
	return ret;
}

int main(void)
{
	int ret = 1;

	uint16_t integer = 0;
	unsigned char *byte = (unsigned char *) &integer;

	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_size_set(&a, CLI_VAL_INTEGER_SIZE_16);

	struct cli_val_integer *v;

	cli_val_integer_attr_endianness_set(&a, CLI_VAL_INTEGER_ENDIANNESS_LITTLE);
	v = cli_val_integer_create(&a);
	byte[0] = 0x01;
	byte[1] = 0x00;

	if (!cli_val_integer_parse_binary(v, (const char *) &integer, sizeof(integer)) != 0) {
		fprintf(stderr, "Failed to parse integer.\n");
		goto exit2;
	}

	if (!expect_print(v, "1")) {
		goto exit2;
	}

	cli_val_integer_destroy(v);

	cli_val_integer_attr_endianness_set(&a, CLI_VAL_INTEGER_ENDIANNESS_BIG);
	v = cli_val_integer_create(&a);
	byte[0] = 0x00;
	byte[1] = 0x01;

	if (!cli_val_integer_parse_binary(v, (const char *) &integer, sizeof(integer)) != 0) {
		fprintf(stderr, "Failed to parse integer.\n");
		goto exit2;
	}

	if (!expect_print(v, "1")) {
		goto exit2;
	}

	ret = 0;
exit2:
	cli_val_integer_destroy(v);
exit1:
	cli_val_integer_attr_deinit(&a);
exit0:
	return ret;
}

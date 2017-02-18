#include <stdlib.h>
#include <stdio.h>

#include "cli/val/integer.h"
#include "magic/magic.h"
#include "otrap/otrap.h"

int main(void)
{
	struct test {
		const char *value;
	};

	struct cli_val_integer_attr a;
	cli_val_integer_attr_init(&a);
	cli_val_integer_attr_set_sign(&a, CLI_VAL_INTEGER_SIGN_2SCMPL);
	cli_val_integer_attr_set_size(&a, CLI_VAL_INTEGER_SIZE_8);

	struct test tests[] = {
		{
			.value = "0",
		},
		{
			.value = "1",
		},
		{
			.value = "127",
		},
		{
			.value = "-1",
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
		struct test *test = &tests[i];

		struct cli_val_integer *v = cli_val_integer_create(&a);
		cli_val_integer_parse(v, "0");

		FILE *file = tmpfile();
		fputs(test->value, file);
		fseek(file, 0, SEEK_SET);

		if (!cli_val_integer_scan(v, file)) {
			fprintf(stderr, "Failed to read '%s'\n", test->value);
			fclose(file);
			cli_val_integer_destroy(v);
			cli_val_integer_attr_deinit(&a);
			return 1;
		}

		struct otrap otrap;
		otrap_init(&otrap);

		cli_val_integer_print(v, otrap_file(&otrap));

		char output[255];
		size_t output_size = otrap_read(&otrap, output, sizeof(output));

		size_t expect_size = strlen(test->value);

		if (output_size != expect_size
			|| memcmp(test->value, output, output_size) != 0) {
			fprintf(stderr, "Expected '%s'\n", test->value);
			fprintf(stderr, "Got '%.*s' instead.\n", (int) output_size, output);
			fclose(file);
			otrap_deinit(&otrap);
			cli_val_integer_destroy(v);
			cli_val_integer_attr_deinit(&a);
			return 1;
		}

		fclose(file);
		otrap_deinit(&otrap);
		cli_val_integer_destroy(v);
	}

	cli_val_integer_attr_deinit(&a);

	return 0;
}

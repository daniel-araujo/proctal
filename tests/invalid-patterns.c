#include <stdlib.h>
#include <stdio.h>

#include <cli/pattern.h>

int main(void)
{
	struct test {
		const char *pattern;
		int expected_error;
		int expected_error_compile_offset;
	};

	struct test tests[] = {
		{
			.pattern = "",
			.expected_error = CLI_PATTERN_ERROR_EMPTY_PATTERN,
			.expected_error_compile_offset = 0,
		},
		{
			.pattern = " ",
			.expected_error = CLI_PATTERN_ERROR_EMPTY_PATTERN,
			.expected_error_compile_offset = 0,
		},
		{
			.pattern = "8899",
			.expected_error = CLI_PATTERN_ERROR_MISSING_WHITESPACE,
			.expected_error_compile_offset = 2,
		},
		{
			.pattern = "??99",
			.expected_error = CLI_PATTERN_ERROR_MISSING_WHITESPACE,
			.expected_error_compile_offset = 2,
		},
		{
			.pattern = " x",
			.expected_error = CLI_PATTERN_ERROR_INVALID_PATTERN,
			.expected_error_compile_offset = 1,
		},
		{
			.pattern = "9",
			.expected_error = CLI_PATTERN_ERROR_INVALID_PATTERN,
			.expected_error_compile_offset = 0,
		}
	};

	cli_pattern cp = cli_pattern_create();

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
		struct test *test = &tests[i];

		cli_pattern_new(cp);

		cli_pattern_compile(cp, test->pattern);

		int error = cli_pattern_error(cp);

		if (error == 0) {
			fprintf(
				stderr,
				"Pattern \"%s\" unexpectedly compiled.\n",
				test->pattern);

			return 1;
		} else if (error != test->expected_error) {
			fprintf(
				stderr,
				"Pattern \"%s\" fails with error code %d but was expecting %d.\n",
				test->pattern,
				error,
				test->expected_error);

			return 1;
		}

		int error_compile_offset = cli_pattern_error_compile_offset(cp);

		if (error_compile_offset != test->expected_error_compile_offset) {
			fprintf(
				stderr,
				"Pattern \"%s\" error compile offset is placed at %d but was expected to be at %d.\n",
				test->pattern,
				error_compile_offset,
				test->expected_error_compile_offset);

			return 1;
		}
	}

	return 0;
}

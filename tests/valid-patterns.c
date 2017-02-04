#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cli/pattern.h"

int main(void)
{
	struct test {
		const char *pattern;
		const char *expected_match;
	};

	struct test tests[] = {
		{
			.pattern = "99",
			.expected_match = "\x99",
		},
		{
			.pattern = "99 88",
			.expected_match = "\x99\x88",
		},
		{
			.pattern = "??",
			.expected_match = "\xaa",
		},
		{
			.pattern = "?? 88",
			.expected_match = "\xaa\x88",
		},
		{
			.pattern = "    ??      88        ",
			.expected_match = "\xaa\x88",
		},
	};

	cli_pattern cp = cli_pattern_create();

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
		struct test *test = &tests[i];

		cli_pattern_new(cp);

		cli_pattern_compile(cp, test->pattern);

		int error = cli_pattern_error(cp);

		if (error) {
			fprintf(
				stderr,
				"Pattern \"%s\" fails with error code %d.\n",
				test->pattern,
				error);

			return 1;
		}

		cli_pattern_input(cp, test->expected_match, strlen(test->expected_match));

		if (!cli_pattern_finished(cp)) {
			fprintf(
				stderr,
				"Pattern \"%s\" could not match the whole thing.\n",
				test->pattern);

			return 1;
		}

		if (!cli_pattern_matched(cp)) {
			fprintf(
				stderr,
				"Pattern \"%s\" failed to match.\n",
				test->pattern);

			return 1;
		}
	}

	return 0;
}

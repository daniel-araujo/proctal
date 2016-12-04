#include <scanner.h>

static inline int match_char(const char *chars, int ch)
{
	for (size_t i = 0; chars[i] != '\0'; ++i) {
		if (chars[i] == ch) {
			return 1;
		}
	}

	return 0;
}

size_t cli_scan_skip_chars(FILE *f, const char *chars)
{
	int ch;
	size_t skipped = 0;

	do {
		ch = fgetc(f);

		if (ch == EOF) {
			return skipped;
		}

		++skipped;
	} while (match_char(chars, ch));

	ungetc(ch, f);

	return skipped;
}

size_t cli_scan_skip_until_chars(FILE *f, const char *chars)
{
	int ch;
	size_t skipped = 0;

	do {
		ch = fgetc(f);

		if (ch == EOF) {
			return skipped;
		}

		++skipped;
	} while (!match_char(chars, ch));

	ungetc(ch, f);

	return skipped;
}

#include "cli/parser/parser.h"

static inline int match_char(const char *chars, char ch)
{
	for (size_t i = 0; chars[i] != '\0'; ++i) {
		if (chars[i] == ch) {
			return 1;
		}
	}

	return 0;
}

size_t cli_parse_skip_chars(const char *s, const char *chars)
{
	int ch;
	size_t skipped = 0;

	for (size_t i = 0; (ch = s[i]) && match_char(chars, ch); ++i) {
		++skipped;
	}

	return skipped;
}

size_t cli_parse_skip_chars2(const char *s, size_t length, const char *chars)
{
	size_t skipped = 0;

	for (const char *ch = s; ch != &s[length] && match_char(chars, *ch); ++ch) {
		++skipped;
	}

	return skipped;
}

size_t cli_parse_skip_until_chars(const char *s, const char *chars)
{
	int ch;
	size_t skipped = 0;

	for (size_t i = 0; (ch = s[i]) && !match_char(chars, ch); ++i) {
		++skipped;
	}

	return skipped;
}

size_t cli_parse_skip_until_chars2(const char *s, size_t length, const char *chars)
{
	size_t skipped = 0;

	for (const char *ch = s; ch != &s[length] && !match_char(chars, *ch); ++ch) {
		++skipped;
	}

	return skipped;
}

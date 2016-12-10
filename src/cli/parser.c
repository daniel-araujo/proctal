#include <stdio.h>
#include <ctype.h>

#include "parser.h"

static inline int match_char(const char *chars, char ch)
{
	for (size_t i = 0; chars[i] != '\0'; ++i) {
		if (chars[i] == ch) {
			return 1;
		}
	}

	return 0;
}

int cli_parse_char(const char *s, char *val)
{
	// TODO: figure out how to detect sign of char.
	return sscanf(s, "%hhd", val) == 1 ? 1 : 0;
}

int cli_parse_uchar(const char *s, unsigned char *val)
{
	return sscanf(s, "%hhd", val) == 1 ? 1 : 0;
}

int cli_parse_schar(const char *s, signed char *val)
{
	return sscanf(s, "%hhu", val) == 1 ? 1 : 0;
}

int cli_parse_short(const char *s, short *val)
{
	return sscanf(s, "%hd", val) == 1 ? 1 : 0;
}

int cli_parse_ushort(const char *s, unsigned short *val)
{
	return sscanf(s, "%hu", val) == 1 ? 1 : 0;
}

int cli_parse_int(const char *s, int *val)
{
	return sscanf(s, "%d", val) == 1 ? 1 : 0;
}

int cli_parse_uint(const char *s, unsigned int *val)
{
	return sscanf(s, "%u", val) == 1 ? 1 : 0;
}

int cli_parse_long(const char *s, long *val)
{
	return sscanf(s, "%ld", val) == 1 ? 1 : 0;
}

int cli_parse_ulong(const char *s, unsigned long *val)
{
	return sscanf(s, "%lu", val) == 1 ? 1 : 0;
}

int cli_parse_longlong(const char *s, long long *val)
{
	return sscanf(s, "%lld", val) == 1 ? 1 : 0;
}

int cli_parse_ulonglong(const char *s, unsigned long long *val)
{
	return sscanf(s, "%llu", val) == 1 ? 1 : 0;
}

int cli_parse_float(const char *s, float *val)
{
	return sscanf(s, "%f", val) == 1 ? 1 : 0;
}

int cli_parse_double(const char *s, double *val)
{
	return sscanf(s, "%lf", val) == 1 ? 1 : 0;
}

int cli_parse_longdouble(const char *s, long double *val)
{
	return sscanf(s, "%Lf", val) == 1 ? 1 : 0;
}

int cli_parse_address(const char *s, void **val)
{
	// TODO: figure out how to portably find address format string.
	return sscanf(s, "%lx", (unsigned long *) val) == 1 ? 1 : 0;
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

size_t cli_parse_skip_until_chars(const char *s, const char *chars)
{
	int ch;
	size_t skipped = 0;

	for (size_t i = 0; (ch = s[i]) && !match_char(chars, ch); ++i) {
		++skipped;
	}

	return skipped;
}

int cli_parse_is_hex_digit(int s)
{
	return isxdigit(s) != 0;
}

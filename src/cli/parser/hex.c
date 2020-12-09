#include <ctype.h>

int cli_parse_is_hex_digit(int s)
{
	return isxdigit(s) != 0;
}

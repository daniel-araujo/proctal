#include <assert.h>

#include "cli/val/integer.h"

static void reverse_bytes(void *p, size_t n)
{
	unsigned char tmp;

	char *low = p;
	char *high = low + n - 1;

	while (high > low)
	{
		tmp = *low;
		*low++ = *high;
		*high-- = tmp;
	}
}

void cli_val_integer_endianness_convert(struct cli_val_integer *v)
{
#if PROCTAL_INTEGER_ENDIANNESS_LITTLE
	if (v->attr.endianness == CLI_VAL_INTEGER_ENDIANNESS_BIG) {
		reverse_bytes(v->data, cli_val_integer_sizeof(v));
	}
#elif PROCTAL_INTEGER_ENDIANNESS_BIG
	if (v->attr.endianness == CLI_VAL_INTEGER_ENDIANNESS_LITTLE) {
		reverse_bytes(v->data, cli_val_integer_sizeof(v));
	}
#else
	#error "Unknown integer endianness."
#endif
}

void cli_val_integer_endianness_revert(struct cli_val_integer *v)
{
	// Basically the same behavior.
	cli_val_integer_endianness_convert(v);
}

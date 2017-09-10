#include <assert.h>

#include "cli/val/integer.h"
#include "magic/magic.h"

int cli_val_integer_unsigned_add(struct cli_val_integer *v, struct cli_val_integer *other_v)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		DEREF(uint8_t, v->data) = DEREF(uint8_t, v->data) + DEREF(uint8_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_16:
		DEREF(uint16_t, v->data) = DEREF(uint16_t, v->data) + DEREF(uint16_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_32:
		DEREF(uint32_t, v->data) = DEREF(uint32_t, v->data) + DEREF(uint32_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_64:
		DEREF(uint64_t, v->data) = DEREF(uint64_t, v->data) + DEREF(uint64_t, other_v->data);
		return 1;
	}

	return 0;
}

int cli_val_integer_unsigned_sub(struct cli_val_integer *v, struct cli_val_integer *other_v)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		DEREF(uint8_t, v->data) = DEREF(uint8_t, v->data) - DEREF(uint8_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_16:
		DEREF(uint16_t, v->data) = DEREF(uint16_t, v->data) - DEREF(uint16_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_32:
		DEREF(uint32_t, v->data) = DEREF(uint32_t, v->data) - DEREF(uint32_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_64:
		DEREF(uint64_t, v->data) = DEREF(uint64_t, v->data) - DEREF(uint64_t, other_v->data);
		return 1;
	}

	return 0;
}

int cli_val_integer_unsigned_cmp(struct cli_val_integer *v, struct cli_val_integer *other_v)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return COMPARE(DEREF(uint8_t, v->data), DEREF(uint8_t, other_v->data));

	case CLI_VAL_INTEGER_BITS_16:
		return COMPARE(DEREF(uint16_t, v->data), DEREF(uint16_t, other_v->data));

	case CLI_VAL_INTEGER_BITS_32:
		return COMPARE(DEREF(uint32_t, v->data), DEREF(uint32_t, other_v->data));

	case CLI_VAL_INTEGER_BITS_64:
		return COMPARE(DEREF(uint64_t, v->data), DEREF(uint64_t, other_v->data));
	}

	return 0;
}

int cli_val_integer_unsigned_print(struct cli_val_integer *v, FILE *f)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return fprintf(f, "%" PRIu8, DEREF(uint8_t, v->data));

	case CLI_VAL_INTEGER_BITS_16:
		return fprintf(f, "%" PRIu16, DEREF(uint16_t, v->data));

	case CLI_VAL_INTEGER_BITS_32:
		return fprintf(f, "%" PRIu32, DEREF(uint32_t, v->data));

	case CLI_VAL_INTEGER_BITS_64:
		return fprintf(f, "%" PRIu64, DEREF(uint64_t, v->data));
	}

	return 0;
}

int cli_val_integer_unsigned_scan(struct cli_val_integer *v, FILE *f)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return fscanf(f, "%" SCNu8, (uint8_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_16:
		return fscanf(f, "%" SCNu16, (uint16_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_32:
		return fscanf(f, "%" SCNu32, (uint32_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_64:
		return fscanf(f, "%" SCNu64, (uint64_t *) v->data) == 1 ? 1 : 0;
	}

	return 0;
}

int cli_val_integer_unsigned_parse_text(struct cli_val_integer *v, const char *s)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return sscanf(s, "%" SCNu8, (uint8_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_16:
		return sscanf(s, "%" SCNu16, (uint16_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_32:
		return sscanf(s, "%" SCNu32, (uint32_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_64:
		return sscanf(s, "%" SCNu64, (uint64_t *) v->data) == 1 ? 1 : 0;
	}

	return 0;
}

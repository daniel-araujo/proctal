#include <assert.h>

#include "cli/val/integer.h"
#include "magic/magic.h"

int cli_val_integer_signed_add(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		DEREF(int8_t, v->data) = DEREF(int8_t, v->data) + DEREF(int8_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_16:
		DEREF(int16_t, v->data) = DEREF(int16_t, v->data) + DEREF(int16_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_32:
		DEREF(int32_t, v->data) = DEREF(int32_t, v->data) + DEREF(int32_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_64:
		DEREF(int64_t, v->data) = DEREF(int64_t, v->data) + DEREF(int64_t, other_v->data);
		return 1;
	}

	return 0;
}

int cli_val_integer_signed_sub(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		DEREF(int8_t, v->data) = DEREF(int8_t, v->data) - DEREF(int8_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_16:
		DEREF(int16_t, v->data) = DEREF(int16_t, v->data) - DEREF(int16_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_32:
		DEREF(int32_t, v->data) = DEREF(int32_t, v->data) - DEREF(int32_t, other_v->data);
		return 1;

	case CLI_VAL_INTEGER_BITS_64:
		DEREF(int64_t, v->data) = DEREF(int64_t, v->data) - DEREF(int64_t, other_v->data);
		return 1;
	}

	return 0;
}

int cli_val_integer_signed_cmp(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return COMPARE(DEREF(int8_t, v->data), DEREF(int8_t, other_v->data));

	case CLI_VAL_INTEGER_BITS_16:
		return COMPARE(DEREF(int16_t, v->data), DEREF(int16_t, other_v->data));

	case CLI_VAL_INTEGER_BITS_32:
		return COMPARE(DEREF(int32_t, v->data), DEREF(int32_t, other_v->data));

	case CLI_VAL_INTEGER_BITS_64:
		return COMPARE(DEREF(int64_t, v->data), DEREF(int64_t, other_v->data));
	}

	return 0;
}

int cli_val_integer_signed_print(struct cli_val_integer *v, FILE *f)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return fprintf(f, "%" PRIi8, DEREF(int8_t, v->data));

	case CLI_VAL_INTEGER_BITS_16:
		return fprintf(f, "%" PRIi16, DEREF(int16_t, v->data));

	case CLI_VAL_INTEGER_BITS_32:
		return fprintf(f, "%" PRIi32, DEREF(int32_t, v->data));

	case CLI_VAL_INTEGER_BITS_64:
		return fprintf(f, "%" PRIi64, DEREF(int64_t, v->data));
	}

	return 0;
}

int cli_val_integer_signed_scan(struct cli_val_integer *v, FILE *f)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return fscanf(f, "%" SCNi8, (int8_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_16:
		return fscanf(f, "%" SCNi16, (int16_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_32:
		return fscanf(f, "%" SCNi32, (int32_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_64:
		return fscanf(f, "%" SCNi64, (int64_t *) v->data) == 1 ? 1 : 0;
	}

	return 0;
}

int cli_val_integer_signed_parse_text(struct cli_val_integer *v, const char *s)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return sscanf(s, "%" SCNi8, (int8_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_16:
		return sscanf(s, "%" SCNi16, (int16_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_32:
		return sscanf(s, "%" SCNi32, (int32_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_BITS_64:
		return sscanf(s, "%" SCNi64, (int64_t *) v->data) == 1 ? 1 : 0;
	}

	return 0;
}

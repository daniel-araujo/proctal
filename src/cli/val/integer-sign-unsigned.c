#include <assert.h>

#include "cli/val/integer.h"
#include "cli/val/native.h"

int cli_val_integer_unsigned_add(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return NATIVE_ADD(uint8_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_16:
		return NATIVE_ADD(uint16_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_32:
		return NATIVE_ADD(uint32_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_64:
		return NATIVE_ADD(uint64_t, v->data, other_v->data);
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_unsigned_sub(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return NATIVE_SUB(uint8_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_16:
		return NATIVE_SUB(uint16_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_32:
		return NATIVE_SUB(uint32_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_64:
		return NATIVE_SUB(uint64_t, v->data, other_v->data);
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_unsigned_cmp(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return NATIVE_CMP(uint8_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_16:
		return NATIVE_CMP(uint16_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_32:
		return NATIVE_CMP(uint32_t, v->data, other_v->data);

	case CLI_VAL_INTEGER_SIZE_64:
		return NATIVE_CMP(uint64_t, v->data, other_v->data);
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_unsigned_print(struct cli_val_integer *v, FILE *f)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return fprintf(f, "%" PRIu8, DEREF(uint8_t, v->data));

	case CLI_VAL_INTEGER_SIZE_16:
		return fprintf(f, "%" PRIu16, DEREF(uint16_t, v->data));

	case CLI_VAL_INTEGER_SIZE_32:
		return fprintf(f, "%" PRIu32, DEREF(uint32_t, v->data));

	case CLI_VAL_INTEGER_SIZE_64:
		return fprintf(f, "%" PRIu64, DEREF(uint64_t, v->data));
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_unsigned_scan(struct cli_val_integer *v, FILE *f)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return fscanf(f, "%" SCNu8, (uint8_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_16:
		return fscanf(f, "%" SCNu16, (uint16_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_32:
		return fscanf(f, "%" SCNu32, (uint32_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_64:
		return fscanf(f, "%" SCNu64, (uint64_t *) v->data) == 1 ? 1 : 0;
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_unsigned_parse(struct cli_val_integer *v, const char *s)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return sscanf(s, "%" SCNu8, (uint8_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_16:
		return sscanf(s, "%" SCNu16, (uint16_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_32:
		return sscanf(s, "%" SCNu32, (uint32_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_64:
		return sscanf(s, "%" SCNu64, (uint64_t *) v->data) == 1 ? 1 : 0;
	}

	// Not expecting to ever reach here.
	assert(0);
}

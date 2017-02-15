#include <assert.h>

#include "cli/val/integer.h"
#include "cli/val/native.h"

int cli_val_integer_2scmpl_add(
	struct cli_val_integer *v1,
	struct cli_val_integer *v2,
	struct cli_val_integer *vr)
{
	switch (vr->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return NATIVE_ADD(int8_t, v1->data, v2->data, vr->data);

	case CLI_VAL_INTEGER_SIZE_16:
		return NATIVE_ADD(int16_t, v1->data, v2->data, vr->data);

	case CLI_VAL_INTEGER_SIZE_32:
		return NATIVE_ADD(int32_t, v1->data, v2->data, vr->data);

	case CLI_VAL_INTEGER_SIZE_64:
		return NATIVE_ADD(int64_t, v1->data, v2->data, vr->data);
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_2scmpl_sub(
	struct cli_val_integer *v1,
	struct cli_val_integer *v2,
	struct cli_val_integer *vr)
{
	switch (vr->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return NATIVE_SUB(int8_t, v1->data, v2->data, vr->data);

	case CLI_VAL_INTEGER_SIZE_16:
		return NATIVE_SUB(int16_t, v1->data, v2->data, vr->data);

	case CLI_VAL_INTEGER_SIZE_32:
		return NATIVE_SUB(int32_t, v1->data, v2->data, vr->data);

	case CLI_VAL_INTEGER_SIZE_64:
		return NATIVE_SUB(int64_t, v1->data, v2->data, vr->data);
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_2scmpl_cmp(
	struct cli_val_integer *v1,
	struct cli_val_integer *v2)
{
	switch (v1->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return NATIVE_CMP(int8_t, v1->data, v2->data);

	case CLI_VAL_INTEGER_SIZE_16:
		return NATIVE_CMP(int16_t, v1->data, v2->data);

	case CLI_VAL_INTEGER_SIZE_32:
		return NATIVE_CMP(int32_t, v1->data, v2->data);

	case CLI_VAL_INTEGER_SIZE_64:
		return NATIVE_CMP(int64_t, v1->data, v2->data);
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_2scmpl_print(struct cli_val_integer *v, FILE *f)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return fprintf(f, "%" PRIi8, DEREF(int8_t, v->data));

	case CLI_VAL_INTEGER_SIZE_16:
		return fprintf(f, "%" PRIi16, DEREF(int16_t, v->data));

	case CLI_VAL_INTEGER_SIZE_32:
		return fprintf(f, "%" PRIi32, DEREF(int32_t, v->data));

	case CLI_VAL_INTEGER_SIZE_64:
		return fprintf(f, "%" PRIi64, DEREF(int64_t, v->data));
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_2scmpl_scan(struct cli_val_integer *v, FILE *f)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return fscanf(f, "%" SCNi8, (int8_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_16:
		return fscanf(f, "%" SCNi16, (int16_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_32:
		return fscanf(f, "%" SCNi32, (int32_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_64:
		return fscanf(f, "%" SCNi64, (int64_t *) v->data) == 1 ? 1 : 0;
	}

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_2scmpl_parse(struct cli_val_integer *v, const char *s)
{
	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		return sscanf(s, "%" SCNi8, (int8_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_16:
		return sscanf(s, "%" SCNi16, (int16_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_32:
		return sscanf(s, "%" SCNi32, (int32_t *) v->data) == 1 ? 1 : 0;

	case CLI_VAL_INTEGER_SIZE_64:
		return sscanf(s, "%" SCNi64, (int64_t *) v->data) == 1 ? 1 : 0;
	}

	// Not expecting to ever reach here.
	assert(0);
}

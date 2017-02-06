#include "cli/val/integer.h"
#include "magic/magic.h"

void cli_val_integer_attr_init(struct cli_val_integer_attr *a);

void cli_val_integer_attr_set_endianness(
	struct cli_val_integer_attr *a,
	enum cli_val_integer_endianness endianness);

void cli_val_integer_attr_set_size(
	struct cli_val_integer_attr *a,
	enum cli_val_integer_size size);

void cli_val_integer_attr_set_sign(
	struct cli_val_integer_attr *a,
	enum cli_val_integer_sign sign);

size_t cli_val_integer_attr_alignof(struct cli_val_integer_attr *a);

void cli_val_integer_attr_deinit(struct cli_val_integer_attr *a);

struct cli_val_integer *cli_val_integer_create(struct cli_val_integer_attr *a);

void cli_val_integer_destroy(struct cli_val_integer *v);

void *cli_val_integer_raw(struct cli_val_integer *v);

size_t cli_val_integer_alignof(struct cli_val_integer *v);

size_t cli_val_integer_sizeof(struct cli_val_integer *v);

int cli_val_integer_parse_bin(struct cli_val_integer *v, const char *s, size_t length);

struct cli_val_integer *cli_val_integer_create_clone(struct cli_val_integer *other_v);

int cli_val_integer_add(
	struct cli_val_integer *v1,
	struct cli_val_integer *v2,
	struct cli_val_integer *vr)
{
#define NATIVE_ADD(TYPE) \
	(DEREF(TYPE, vr->data) = DEREF(TYPE, v1->data) + DEREF(TYPE, v2->data)), 1

	switch (vr->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		if (vr->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_ADD(uint8_t);
		} else {
			return NATIVE_ADD(int8_t);
		}

	case CLI_VAL_INTEGER_SIZE_16:
		if (vr->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_ADD(uint16_t);
		} else {
			return NATIVE_ADD(int16_t);
		}

	case CLI_VAL_INTEGER_SIZE_32:
		if (vr->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_ADD(uint32_t);
		} else {
			return NATIVE_ADD(int32_t);
		}

	case CLI_VAL_INTEGER_SIZE_64:
		if (vr->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_ADD(uint64_t);
		} else {
			return NATIVE_ADD(int64_t);
		}
	}

#undef NATIVE_ADD

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_sub(
	struct cli_val_integer *v1,
	struct cli_val_integer *v2,
	struct cli_val_integer *vr)
{
#define NATIVE_SUB(TYPE) \
	(DEREF(TYPE, vr->data) = DEREF(TYPE, v1->data) - DEREF(TYPE, v2->data)), 1

	switch (vr->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		if (vr->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_SUB(uint8_t);
		} else {
			return NATIVE_SUB(int8_t);
		}

	case CLI_VAL_INTEGER_SIZE_16:
		if (vr->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_SUB(uint16_t);
		} else {
			return NATIVE_SUB(int16_t);
		}

	case CLI_VAL_INTEGER_SIZE_32:
		if (vr->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_SUB(uint32_t);
		} else {
			return NATIVE_SUB(int32_t);
		}

	case CLI_VAL_INTEGER_SIZE_64:
		if (vr->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_SUB(uint64_t);
		} else {
			return NATIVE_SUB(int64_t);
		}
	}

#undef NATIVE_SUB

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_cmp(
	struct cli_val_integer *v1,
	struct cli_val_integer *v2)
{
#define NATIVE_CMP(TYPE) \
	COMPARE(DEREF(TYPE, v1->data), DEREF(TYPE, v2->data))

	switch (v1->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		if (v1->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_CMP(uint8_t);
		} else {
			return NATIVE_CMP(int8_t);
		}

	case CLI_VAL_INTEGER_SIZE_16:
		if (v1->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_CMP(uint16_t);
		} else {
			return NATIVE_CMP(int16_t);
		}

	case CLI_VAL_INTEGER_SIZE_32:
		if (v1->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_CMP(uint32_t);
		} else {
			return NATIVE_CMP(int32_t);
		}

	case CLI_VAL_INTEGER_SIZE_64:
		if (v1->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return NATIVE_CMP(uint64_t);
		} else {
			return NATIVE_CMP(int64_t);
		}
	}

#undef NATIVE_CMP

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_print(struct cli_val_integer *v, FILE *f)
{
#define PRINTF(FORMAT, TYPE) \
	fprintf(f, FORMAT, DEREF(TYPE, v->data))

	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return PRINTF("%" PRIu8, uint8_t);
		} else {
			return PRINTF("%" PRIi8, int8_t);
		}

	case CLI_VAL_INTEGER_SIZE_16:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return PRINTF("%" PRIu16, uint16_t);
		} else {
			return PRINTF("%" PRIi16, int16_t);
		}

	case CLI_VAL_INTEGER_SIZE_32:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return PRINTF("%" PRIu32, uint32_t);
		} else {
			return PRINTF("%" PRIi32, int32_t);
		}

	case CLI_VAL_INTEGER_SIZE_64:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return PRINTF("%" PRIu64, uint64_t);
		} else {
			return PRINTF("%" PRIi64, int64_t);
		}
	}

#undef PRINTF

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_scan(struct cli_val_integer *v, FILE *f)
{
#define SCANF(FORMAT, TYPE) \
	(fscanf(f, FORMAT, (TYPE *) v->data) == 1 ? 1 : 0)

	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return SCANF("%" SCNu8, uint8_t);
		} else {
			return SCANF("%" SCNi8, int8_t);
		}

	case CLI_VAL_INTEGER_SIZE_16:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return SCANF("%" SCNu16, uint16_t);
		} else {
			return SCANF("%" SCNi16, int16_t);
		}

	case CLI_VAL_INTEGER_SIZE_32:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return SCANF("%" SCNu32, uint32_t);
		} else {
			return SCANF("%" SCNi32, int32_t);
		}

	case CLI_VAL_INTEGER_SIZE_64:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return SCANF("%" SCNu64, uint64_t);
		} else {
			return SCANF("%" SCNi64, int64_t);
		}
	}

#undef SCANF

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_integer_parse(struct cli_val_integer *v, const char *s)
{
#define SCANF(FORMAT, TYPE) \
	(sscanf(s, FORMAT, (TYPE *) v->data) == 1 ? 1 : 0)

	switch (v->attr.size) {
	case CLI_VAL_INTEGER_SIZE_8:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return SCANF("%" SCNu8, uint8_t);
		} else {
			return SCANF("%" SCNi8, int8_t);
		}

	case CLI_VAL_INTEGER_SIZE_16:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return SCANF("%" SCNu16, uint16_t);
		} else {
			return SCANF("%" SCNi16, int16_t);
		}

	case CLI_VAL_INTEGER_SIZE_32:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return SCANF("%" SCNu32, uint32_t);
		} else {
			return SCANF("%" SCNi32, int32_t);
		}

	case CLI_VAL_INTEGER_SIZE_64:
		if (v->attr.sign == CLI_VAL_INTEGER_SIGN_UNSIGNED) {
			return SCANF("%" SCNu64, uint64_t);
		} else {
			return SCANF("%" SCNi64, int64_t);
		}
	}

#undef SCANF

	// Not expecting to ever reach here.
	assert(0);
}

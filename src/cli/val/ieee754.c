#include "cli/val/ieee754.h"

void cli_val_ieee754_attr_init(struct cli_val_ieee754_attr *a);

void cli_val_ieee754_attr_set_precision(
	struct cli_val_ieee754_attr *a,
	enum cli_val_ieee754_precision precision);

size_t cli_val_ieee754_attr_alignof(struct cli_val_ieee754_attr *a);

void cli_val_ieee754_attr_deinit(struct cli_val_ieee754_attr *a);

struct cli_val_ieee754 *cli_val_ieee754_create(struct cli_val_ieee754_attr *a);

void cli_val_ieee754_destroy(struct cli_val_ieee754 *v);

void *cli_val_ieee754_raw(struct cli_val_ieee754 *v);

size_t cli_val_ieee754_alignof(struct cli_val_ieee754 *v);

size_t cli_val_ieee754_sizeof(struct cli_val_ieee754 *v);

int cli_val_ieee754_parse_bin(struct cli_val_ieee754 *v, const char *s, size_t length);

struct cli_val_ieee754 *cli_val_ieee754_create_clone(struct cli_val_ieee754 *other_v);

int cli_val_ieee754_add(
	struct cli_val_ieee754 *v1,
	struct cli_val_ieee754 *v2,
	struct cli_val_ieee754 *vr)
{
#define NATIVE_ADD(TYPE) \
	*(TYPE*) vr->data = *(TYPE*) v1->data + *(TYPE*) v2->data; \
	return 1;

	switch (vr->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		NATIVE_ADD(float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		NATIVE_ADD(double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		NATIVE_ADD(long double);
	}

#undef NATIVE_ADD

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_ieee754_sub(
	struct cli_val_ieee754 *v1,
	struct cli_val_ieee754 *v2,
	struct cli_val_ieee754 *vr)
{
#define NATIVE_SUB(TYPE) \
	*(TYPE*) vr->data = *(TYPE*) v1->data - *(TYPE*) v2->data; \
	return 1;

	switch (vr->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		NATIVE_SUB(float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		NATIVE_SUB(double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		NATIVE_SUB(long double);
	}

#undef NATIVE_SUB

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_ieee754_cmp(
	struct cli_val_ieee754 *v1,
	struct cli_val_ieee754 *v2)
{
#define NATIVE_CMP(TYPE) \
	(*(TYPE*) v1->data == *(TYPE*) v2->data \
		? 0 \
		: (*(TYPE*) v1->data > *(TYPE*) v2->data ? 1 : -1))

	switch (v1->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return NATIVE_CMP(float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return NATIVE_CMP(double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return NATIVE_CMP(long double);
	}

#undef NATIVE_CMP

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_ieee754_print(struct cli_val_ieee754 *v, FILE *f)
{
#define PRINTF(FORMAT, TYPE) \
	fprintf(f, FORMAT, *(TYPE *) v->data)

	switch (v->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return PRINTF("%f", float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return PRINTF("%f", double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return PRINTF("%Lf", long double);
	}

#undef PRINTF

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_ieee754_scan(struct cli_val_ieee754 *v, FILE *f)
{
#define SCANF(FORMAT, TYPE) \
	(fscanf(f, FORMAT, (TYPE *) v->data) == 1 ? 1 : 0)

	switch (v->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return SCANF("%f", float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return SCANF("%lf", double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return SCANF("%Lf", long double);
	}

#undef SCANF

	// Not expecting to ever reach here.
	assert(0);
}

int cli_val_ieee754_parse(struct cli_val_ieee754 *v, const char *s)
{
#define SCANF(FORMAT, TYPE) \
	(sscanf(s, FORMAT, (TYPE *) v->data) == 1 ? 1 : 0)

	switch (v->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return SCANF("%f", float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return SCANF("%lf", double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return SCANF("%Lf", long double);
	}

#undef SCANF

	// Not expecting to ever reach here.
	assert(0);
}

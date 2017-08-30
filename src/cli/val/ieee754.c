#include "cli/val/ieee754.h"
#include "magic/magic.h"

extern inline void cli_val_ieee754_attr_init(struct cli_val_ieee754_attr *a);

extern inline void cli_val_ieee754_attr_precision_set(
	struct cli_val_ieee754_attr *a,
	enum cli_val_ieee754_precision precision);

extern inline size_t cli_val_ieee754_attr_alignof(
	struct cli_val_ieee754_attr *a);

extern inline void cli_val_ieee754_attr_deinit(struct cli_val_ieee754_attr *a);

extern inline struct cli_val_ieee754 *cli_val_ieee754_create(
	struct cli_val_ieee754_attr *a);

extern inline void cli_val_ieee754_destroy(struct cli_val_ieee754 *v);

extern inline void *cli_val_ieee754_data(struct cli_val_ieee754 *v);

extern inline size_t cli_val_ieee754_alignof(struct cli_val_ieee754 *v);

extern inline size_t cli_val_ieee754_sizeof(struct cli_val_ieee754 *v);

extern inline int cli_val_ieee754_parse_binary(
	struct cli_val_ieee754 *v,
	const char *s,
	size_t length);

extern inline struct cli_val_ieee754 *cli_val_ieee754_create_clone(
	struct cli_val_ieee754 *other_v);

int cli_val_ieee754_add(
	struct cli_val_ieee754 *v,
	struct cli_val_ieee754 *other_v)
{
#define NATIVE_ADD(TYPE) \
	(DEREF(TYPE, v->data) = DEREF(TYPE, v->data) + DEREF(TYPE, other_v->data)), 1

	switch (v->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return NATIVE_ADD(float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return NATIVE_ADD(double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return NATIVE_ADD(long double);
	}

#undef NATIVE_ADD

	return 0;
}

int cli_val_ieee754_sub(
	struct cli_val_ieee754 *v,
	struct cli_val_ieee754 *other_v)
{
#define NATIVE_SUB(TYPE) \
	(DEREF(TYPE, v->data) = DEREF(TYPE, v->data) - DEREF(TYPE, other_v->data)), 1

	switch (v->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return NATIVE_SUB(float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return NATIVE_SUB(double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return NATIVE_SUB(long double);
	}

#undef NATIVE_SUB

	return 0;
}

int cli_val_ieee754_cmp(
	struct cli_val_ieee754 *v,
	struct cli_val_ieee754 *other_v)
{
#define NATIVE_CMP(TYPE) \
	COMPARE(DEREF(TYPE, v->data), DEREF(TYPE, other_v->data))

	switch (v->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return NATIVE_CMP(float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return NATIVE_CMP(double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return NATIVE_CMP(long double);
	}

#undef NATIVE_CMP

	return 0;
}

int cli_val_ieee754_print(struct cli_val_ieee754 *v, FILE *f)
{
#define PRINTF(FORMAT, TYPE) \
	fprintf(f, FORMAT, DEREF(TYPE, v->data))

	switch (v->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return PRINTF("%g", float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return PRINTF("%g", double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return PRINTF("%Lg", long double);
	}

#undef PRINTF

	return 0;
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

	return 0;
}

int cli_val_ieee754_parse_text(struct cli_val_ieee754 *v, const char *s)
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

	return 0;
}

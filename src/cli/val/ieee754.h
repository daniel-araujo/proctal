#ifndef CLI_VAL_IEEE754_H
#define CLI_VAL_IEEE754_H

#include <stdlib.h>
#include <stdio.h>
#include <stdalign.h>
#include <assert.h>
#include <string.h>

/*
 * Supported floating point precision.
 */
enum cli_val_ieee754_precision {
	CLI_VAL_IEEE754_PRECISION_SINGLE = 4,
	CLI_VAL_IEEE754_PRECISION_DOUBLE = 8,
	CLI_VAL_IEEE754_PRECISION_EXTENDED = 10,
};

/*
 * Describes the behavior of a floating point value.
 */
struct cli_val_ieee754_attr {
	enum cli_val_ieee754_precision precision;
};

/*
 * How our floating point values are represented in memory.
 */
struct cli_val_ieee754 {
	// Describes the behavior of the floating point value.
	struct cli_val_ieee754_attr attr;

	// Where the actual data is stored. The length of this data member
	// depends on the precision of the floating point value.
	union {
		// The following members allows data to be casted to those
		// types without breaking strict aliasing rules.
		float a;
		double b;
		long double c;
	} data[0];
};

/*
 * Sets the initial state of floating point value attributes.
 */
inline void cli_val_ieee754_attr_init(struct cli_val_ieee754_attr *a)
{
	a->precision = CLI_VAL_IEEE754_PRECISION_SINGLE;
}

/*
 * Sets precision.
 */
inline void cli_val_ieee754_attr_set_precision(
	struct cli_val_ieee754_attr *a,
	enum cli_val_ieee754_precision precision)
{
	a->precision = precision;
}

/*
 * Returns alignment requirements.
 */
inline size_t cli_val_ieee754_attr_alignof(struct cli_val_ieee754_attr *a)
{
	switch (a->precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return alignof(float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return alignof(double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return alignof(long double);
	}

	// Not expecting to ever reach here.
	assert(0);
}

/*
 * Disposes it off.
 */
inline void cli_val_ieee754_attr_deinit(struct cli_val_ieee754_attr *a)
{
}

/*
 * Creates a floating point value obeying the given attributes.
 *
 * By default value yields garbage.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_ieee754 *cli_val_ieee754_create(struct cli_val_ieee754_attr *a)
{
	// Taking advantage of the fact that the values for the constants are
	// encoded in their corresponding length in bytes.
	size_t size = a->precision;

	struct cli_val_ieee754 *v = malloc(sizeof(*v) + size);

	if (v == NULL) {
		return NULL;
	}

	v->attr = *a;

	return v;
}

/*
 * Destroys a floating point value created by a call to cli_val_ieee754_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_ieee754_destroy(struct cli_val_ieee754 *v)
{
	free(v);
}

/*
 * Returns a pointer to the raw data that represents the floating point value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_ieee754_raw(struct cli_val_ieee754 *v)
{
	return v->data;
}

/*
 * Alignment requirements.
 */
inline size_t cli_val_ieee754_alignof(struct cli_val_ieee754 *v)
{
	return cli_val_ieee754_attr_alignof(&v->attr);
}

/*
 * Size of the floating point value.
 */
inline size_t cli_val_ieee754_sizeof(struct cli_val_ieee754 *v)
{
	switch (v->attr.precision) {
	case CLI_VAL_IEEE754_PRECISION_SINGLE:
		return sizeof(float);

	case CLI_VAL_IEEE754_PRECISION_DOUBLE:
		return sizeof(double);

	case CLI_VAL_IEEE754_PRECISION_EXTENDED:
		return sizeof(long double);
	}

	// Not expecting to ever reach here.
	assert(0);
}

/*
 * Attempts to interpret a floating point value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_ieee754_parse_bin(struct cli_val_ieee754 *v, const char *s, size_t length)
{
	size_t size = cli_val_ieee754_sizeof(v);

	if (size > length) {
		return 0;
	}

	memcpy(cli_val_ieee754_raw(v), s, size);

	return size;
}

/*
 * Creates a new floating point value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_ieee754 *cli_val_ieee754_create_clone(struct cli_val_ieee754 *other_v)
{
	struct cli_val_ieee754 *v = cli_val_ieee754_create(&other_v->attr);

	if (v == NULL) {
		return NULL;
	}

	cli_val_ieee754_parse_bin(v, (void *) other_v->data, cli_val_ieee754_sizeof(v));

	return v;
}

/*
 * Adds the other value.
 */
int cli_val_ieee754_add(
	struct cli_val_ieee754 *v,
	struct cli_val_ieee754 *other_v);

/*
 * Subtracts the other value.
 */
int cli_val_ieee754_sub(
	struct cli_val_ieee754 *v,
	struct cli_val_ieee754 *other_v);

/*
 * Compares two floating point values.
 *
 * Returns 0 if they're equal.
 * Returns 1 if the first value is greater than the second one.
 * Returns -1 if the first value is less than the second one.
 */
int cli_val_ieee754_cmp(
	struct cli_val_ieee754 *v,
	struct cli_val_ieee754 *other_v);

/*
 * Attempts to write the floating point value as text to a file.
 *
 * Returns how many characters were written.
 */
int cli_val_ieee754_print(struct cli_val_ieee754 *v, FILE *f);

/*
 * Attempts to read the floating point value as text from a file.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_ieee754_scan(struct cli_val_ieee754 *v, FILE *f);

/*
 * Attempts to parse the floating point value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_ieee754_parse(struct cli_val_ieee754 *v, const char *s);

#endif /* CLI_VAL_IEEE754_H */

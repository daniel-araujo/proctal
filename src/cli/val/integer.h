#ifndef CLI_VAL_INTEGER_H
#define CLI_VAL_INTEGER_H

#include <stdlib.h>
#include <stdio.h>
#include <stdalign.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

#include "config.h"

/*
 * Supported number of bits.
 */
enum cli_val_integer_bits {
	CLI_VAL_INTEGER_BITS_8 = 1,
	CLI_VAL_INTEGER_BITS_16 = 2,
	CLI_VAL_INTEGER_BITS_32 = 4,
	CLI_VAL_INTEGER_BITS_64 = 8,
};

/*
 * Supported integer signing conventions.
 */
enum cli_val_integer_sign {
	CLI_VAL_INTEGER_SIGN_UNSIGNED,
	CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT,
};

/*
 * Supported endianness types.
 */
enum cli_val_integer_endianness {
	CLI_VAL_INTEGER_ENDIANNESS_LITTLE,
	CLI_VAL_INTEGER_ENDIANNESS_BIG,
};

#define CLI_VAL_INTEGER_BITS_DEFAULT CLI_VAL_INTEGER_BITS_8

#define CLI_VAL_INTEGER_SIGN_DEFAULT CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT

#ifdef PROCTAL_INTEGER_ENDIANNESS_LITTLE

	#define CLI_VAL_INTEGER_ENDIANNESS_DEFAULT CLI_VAL_INTEGER_ENDIANNESS_LITTLE

#elif defined PROCTAL_INTEGER_ENDIANNESS_BIG

	#define CLI_VAL_INTEGER_ENDIANNESS_DEFAULT CLI_VAL_INTEGER_ENDIANNESS_BIG

#else

	#error "Unknown integer endianness."

#endif

/*
 * Describes the behavior of an integer value.
 */
struct cli_val_integer_attr {
	enum cli_val_integer_bits bits;
	enum cli_val_integer_sign sign;
	enum cli_val_integer_endianness endianness;
};

/*
 * How our integer values are represented in memory.
 */
struct cli_val_integer {
	// Describes the behavior of the integer value.
	struct cli_val_integer_attr attr;

	// Where the actual data is stored. The length of this data member
	// depends on the size of the integer.
	union {
		// The following members allows data to be casted to those
		// types without breaking strict aliasing rules.
		uint8_t a;
		uint16_t b;
		uint32_t c;
		uint64_t d;
	} data[0];
};

/*
 * Sets the initial state of integer value attributes.
 */
inline void cli_val_integer_attr_init(struct cli_val_integer_attr *a)
{
	a->bits = CLI_VAL_INTEGER_BITS_DEFAULT;
	a->sign = CLI_VAL_INTEGER_SIGN_DEFAULT;
	a->endianness = CLI_VAL_INTEGER_ENDIANNESS_DEFAULT;
}

/*
 * Sets endianness.
 */
inline void cli_val_integer_attr_endianness_set(struct cli_val_integer_attr *a, enum cli_val_integer_endianness endianness)
{
	a->endianness = endianness;
}

/*
 * Sets number of bits.
 */
inline void cli_val_integer_attr_bits_set(struct cli_val_integer_attr *a, enum cli_val_integer_bits bits)
{
	a->bits = bits;
}

/*
 * Sets sign type.
 */
inline void cli_val_integer_attr_sign_set(struct cli_val_integer_attr *a, enum cli_val_integer_sign sign)
{
	a->sign = sign;
}

/*
 * Returns alignment requirements.
 */
inline size_t cli_val_integer_attr_alignof(struct cli_val_integer_attr *a)
{
	switch (a->bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return alignof(int8_t);

	case CLI_VAL_INTEGER_BITS_16:
		return alignof(int16_t);

	case CLI_VAL_INTEGER_BITS_32:
		return alignof(int32_t);

	case CLI_VAL_INTEGER_BITS_64:
		return alignof(int64_t);
	}

	// Not expecting to ever reach here.
	assert(0);
	return 1;
}

/*
 * Disposes it off.
 */
inline void cli_val_integer_attr_deinit(struct cli_val_integer_attr *a)
{
}

/*
 * Creates an integer value obeying the given attributes.
 *
 * By default the value yields garbage.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_integer *cli_val_integer_create(struct cli_val_integer_attr *a)
{
	// Taking advantage of the fact that the values for the constants are
	// encoded in their corresponding length in bytes.
	size_t size = a->bits;

	struct cli_val_integer *v = malloc(sizeof(*v) + size);

	if (v == NULL) {
		return NULL;
	}

	v->attr = *a;

	return v;
}

/*
 * Destroys an integer value created by a call to cli_val_integer_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_integer_destroy(struct cli_val_integer *v)
{
	free(v);
}

/*
 * Returns a pointer to the raw data that represents the integer value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_integer_data(struct cli_val_integer *v)
{
	return v->data;
}

/*
 * Alignment requirements.
 */
inline size_t cli_val_integer_alignof(struct cli_val_integer *v)
{
	return cli_val_integer_attr_alignof(&v->attr);
}

/*
 * Size of the integer value.
 */
inline size_t cli_val_integer_sizeof(struct cli_val_integer *v)
{
	switch (v->attr.bits) {
	case CLI_VAL_INTEGER_BITS_8:
		return sizeof(int8_t);

	case CLI_VAL_INTEGER_BITS_16:
		return sizeof(int16_t);

	case CLI_VAL_INTEGER_BITS_32:
		return sizeof(int32_t);

	case CLI_VAL_INTEGER_BITS_64:
		return sizeof(int64_t);
	}

	// Not expecting to ever reach here.
	assert(0);
	return 0;
}

/*
 * Attempts to interpret an integer value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_integer_parse_binary(struct cli_val_integer *v, const void *b, size_t length)
{
	size_t size = cli_val_integer_sizeof(v);

	if (size > length) {
		return 0;
	}

	memcpy(cli_val_integer_data(v), b, size);

	return size;
}

/*
 * Creates a new integer value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_integer *cli_val_integer_create_clone(struct cli_val_integer *other_v)
{
	struct cli_val_integer *v = cli_val_integer_create(&other_v->attr);

	if (v == NULL) {
		return NULL;
	}

	cli_val_integer_parse_binary(v, (void *) other_v->data, cli_val_integer_sizeof(v));

	return v;
}

/*
 * Adds the other value.
 */
int cli_val_integer_add(struct cli_val_integer *v, struct cli_val_integer *other_v);

/*
 * Subtracts the other value.
 */
int cli_val_integer_sub(struct cli_val_integer *v, struct cli_val_integer *other_v);

/*
 * Compares two integer values.
 *
 * Returns 0 if they're equal.
 * Returns 1 if the first integer value is greater than the second one.
 * Returns -1 if the first integer value is less than the second one.
 */
int cli_val_integer_cmp(struct cli_val_integer *v, struct cli_val_integer *other_v);

/*
 * Attempts to write the integer value as text to a file.
 *
 * Returns how many characters were written.
 */
int cli_val_integer_print(struct cli_val_integer *v, FILE *f);

/*
 * Attempts to read the integer value as text from a file.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_integer_scan(struct cli_val_integer *v, FILE *f);

/*
 * Attempts to parse the integer value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_integer_parse_text(struct cli_val_integer *v, const char *s);

#endif /* CLI_VAL_INTEGER_H */

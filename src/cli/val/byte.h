#ifndef CLI_VAL_BYTE_H
#define CLI_VAL_BYTE_H

#include <stdlib.h>
#include <stdio.h>
#include <stdalign.h>
#include <assert.h>
#include <string.h>

#include "magic/magic.h"

/*
 * Represents an byte value.
 */
struct cli_val_byte {
	// We're going to assume that on every platform we will support an
	// unsigned char is the same size of a byte.
	unsigned char byte;
};

/*
 * Creates a byte value.
 *
 * By default value yields garbage.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_byte *cli_val_byte_create(void)
{
	struct cli_val_byte *v = malloc(sizeof(*v));

	if (v == NULL) {
		return NULL;
	}

	return v;
}

/*
 * Destroys a byte value created by a call to cli_val_byte_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_byte_destroy(struct cli_val_byte *v)
{
	free(v);
}

/*
 * Returns a pointer to the raw data that represents the byte value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_byte_data(struct cli_val_byte *v)
{
	return &v->byte;
}

/*
 * Attempts to interpret an byte value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_byte_parse_binary(struct cli_val_byte *v, const char *s, size_t length)
{
	size_t size = 1;

	if (size > length) {
		return 0;
	}

	memcpy(cli_val_byte_data(v), s, size);

	return size;
}

/*
 * Adds the other value.
 */
inline int cli_val_byte_add(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v)
{
	v->byte = v->byte + other_v->byte;

	return 1;
}

/*
 * Subtracts the other value.
 */
inline int cli_val_byte_sub(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v)
{
	v->byte = v->byte - other_v->byte;

	return 1;
}

/*
 * Compares two byte values.
 *
 * Returns 0 if they're equal.
 * Returns 1 if the first value is greater than the second one.
 * Returns -1 if the first value is less than the second one.
 */
inline int cli_val_byte_cmp(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v)
{
	return COMPARE(v->byte, other_v->byte);
}

/*
 * Attempts to write the byte value as text to a file.
 *
 * Returns how many characters were written.
 */
inline int cli_val_byte_print(struct cli_val_byte *v, FILE *f)
{
	return fprintf(f, "%02X", v->byte);
}

/*
 * Attempts to read the byte value as text from a file.
 *
 * Returns 1 on success, 0 on failure.
 */
inline int cli_val_byte_scan(struct cli_val_byte *v, FILE *f)
{
	return fscanf(f, "%hhx", &v->byte) == 1 ? 1 : 0;
}

/*
 * Attempts to parse the byte value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
inline int cli_val_byte_parse_text(struct cli_val_byte *v, const char *s)
{
	return sscanf(s, "%hhx", &v->byte) == 1 ? 1 : 0;
}

/*
 * Creates a new byte value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_byte *cli_val_byte_create_clone(struct cli_val_byte *other_v)
{
	struct cli_val_byte *v = cli_val_byte_create();

	if (v == NULL) {
		return NULL;
	}

	v->byte = other_v->byte;

	return v;
}

#endif /* CLI_VAL_BYTE_H */

#ifndef CLI_VAL_ADDRESS_H
#define CLI_VAL_ADDRESS_H

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdalign.h>
#include <assert.h>
#include <string.h>

/*
 * Represents an address value.
 */
struct cli_val_address {
	// This is the value of the address.
	uintptr_t address;
};

/*
 * Alignment requirements.
 */
inline size_t cli_val_address_alignof(void)
{
	return alignof(void *);
}

/*
 * Size of the address value.
 */
inline size_t cli_val_address_sizeof(void)
{
	return sizeof(void *);
}

/*
 * Creates an address value.
 *
 * By default value yields garbage.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_address *cli_val_address_create(void)
{
	struct cli_val_address *v = malloc(sizeof(*v));

	if (v == NULL) {
		return NULL;
	}

	return v;
}

/*
 * Destroys an address value created by a call to cli_val_address_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_address_destroy(struct cli_val_address *v)
{
	free(v);
}

/*
 * Returns a pointer to the raw data that represents the address value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_address_data(struct cli_val_address *v)
{
	return &v->address;
}

/*
 * Attempts to interpret an address value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_address_parse_binary(struct cli_val_address *v, const char *s, size_t length)
{
	size_t size = cli_val_address_sizeof();

	if (size > length) {
		return 0;
	}

	memcpy(cli_val_address_data(v), s, size);

	return size;
}

/*
 * Compares two address values.
 *
 * Returns 0 if they're equal.
 * Returns 1 if the first value is greater than the second one.
 * Returns -1 if the first value is less than the second one.
 */
inline int cli_val_address_cmp(struct cli_val_address *v, struct cli_val_address *other_v)
{
	return v->address == other_v->address
		? 0
		: v->address > other_v->address ? 1 : -1;
}

/*
 * Creates a new address value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_address *cli_val_address_create_clone(struct cli_val_address *other_v)
{
	struct cli_val_address *v = cli_val_address_create();

	if (v == NULL) {
		return NULL;
	}

	v->address = other_v->address;

	return v;
}

/*
 * Attempts to write the address value as text to a file.
 *
 * Returns how many characters were written.
 */
int cli_val_address_print(struct cli_val_address *v, FILE *f);

/*
 * Attempts to read the address value as text from a file.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_address_scan(struct cli_val_address *v, FILE *f);

/*
 * Attempts to parse the address value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_address_parse_text(struct cli_val_address *v, const char *s);

#endif /* CLI_VAL_ADDRESS_H */

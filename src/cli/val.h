#ifndef CLI_VAL_H
#define CLI_VAL_H

#include <stdlib.h>
#include <stdio.h>

#include "cli/val/integer.h"
#include "cli/val/ieee754.h"
#include "cli/val/address.h"
#include "cli/val/byte.h"
#include "cli/val/text.h"
#include "cli/val/instruction.h"

/*
 * Known types.
 */
enum cli_val_type {
	CLI_VAL_TYPE_NIL,
	CLI_VAL_TYPE_BYTE,
	CLI_VAL_TYPE_INTEGER,
	CLI_VAL_TYPE_IEEE754,
	CLI_VAL_TYPE_TEXT,
	CLI_VAL_TYPE_ADDRESS,
	CLI_VAL_TYPE_INSTRUCTION,
};

typedef struct cli_val *cli_val;

/*
 * Wraps a value.
 *
 * Returns nil on failure.
 */
cli_val cli_val_wrap(enum cli_val_type type, void *val);

/*
 * Unwraps a value and destroys the wrapper.
 */
void *cli_val_unwrap(cli_val v);

/*
 * Creates a clone.
 *
 * The clone is independent of the original value and must be destroyed after
 * it's done being used.
 *
 * Returns nil on failure.
 */
cli_val cli_val_create_clone(cli_val other_v);

/*
 * Destroys the value.
 */
void cli_val_destroy(cli_val v);

/*
 * Defines the address if the value supports it.
 */
void cli_val_address_set(cli_val v, void *addr);

/*
 * Returns the address associated with the value.
 */
void *cli_val_address(cli_val v);

/*
 * Returns the type of the value.
 */
enum cli_val_type cli_val_type(cli_val v);

/*
 * Returns alignment requirements of the value.
 */
size_t cli_val_alignof(cli_val v);

/*
 * Returns the size of the value.
 */
size_t cli_val_sizeof(cli_val v);

/*
 * Returns a pointer to the underlying data.
 *
 * The pointer can be dereferenced but you must be sure to know what you're
 * doing.
 */
void *cli_val_raw(cli_val v);

/*
 * Adds the other value.
 */
int cli_val_add(cli_val v, cli_val other_v);

/*
 * Subtracts the other value.
 */
int cli_val_sub(cli_val v, cli_val other_v);

/*
 * Compares two values.
 *
 * Returns 0 if they're equal.
 * Returns 1 if the first is greater than the second.
 * Returns -1 if the first is less than the second.
 */
int cli_val_cmp(cli_val v, cli_val other_v);

/*
 * Attempts to write the value as text to a file.
 *
 * Returns how many characters were written.
 */
int cli_val_print(cli_val v, FILE *f);

/*
 * Attempts to read the value as text from a file.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_scan(cli_val v, FILE *f);

/*
 * Attempts to parse the value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_parse(cli_val v, const char *s);

/*
 * Attempts to interpret a value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
int cli_val_parse_bin(cli_val v, const char *s, size_t length);

/*
 * Returns a value that represents no value. This will always return the same
 * value.
 *
 * Never pass it to a function otherwise the program will crash.
 */
cli_val cli_val_nil(void);

#endif /* CLI_VAL_H */

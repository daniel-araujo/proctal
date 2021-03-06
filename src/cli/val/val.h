#ifndef CLI_VAL_H
#define CLI_VAL_H

#include <stdlib.h>
#include <stdio.h>

#include "cli/val/integer.h"
#include "cli/val/ieee754.h"
#include "cli/val/address.h"
#include "cli/val/byte.h"
#include "cli/val/text.h"
#include "cli/val/x86.h"
#include "cli/val/arm.h"
#include "cli/val/sparc.h"
#include "cli/val/powerpc.h"
#include "cli/val/mips.h"

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
	CLI_VAL_TYPE_X86,
	CLI_VAL_TYPE_ARM,
	CLI_VAL_TYPE_SPARC,
	CLI_VAL_TYPE_POWERPC,
	CLI_VAL_TYPE_MIPS,
};

typedef struct cli_val *cli_val_t;

/*
 * Wraps a value.
 *
 * Returns nil on failure.
 */
cli_val_t cli_val_wrap(enum cli_val_type type, void *val);

/*
 * Unwraps a value and destroys the wrapper.
 */
void *cli_val_unwrap(cli_val_t v);

/*
 * Creates a clone.
 *
 * The clone is independent of the original value and must be destroyed after
 * it's done being used.
 *
 * Returns nil on failure.
 */
cli_val_t cli_val_create_clone(cli_val_t other_v);

/*
 * Destroys the value.
 */
void cli_val_destroy(cli_val_t v);

/*
 * Defines the address if the value supports it.
 */
void cli_val_address_set(cli_val_t v, void *addr);

/*
 * Returns the address associated with the value.
 */
void *cli_val_address(cli_val_t v);

/*
 * Returns the type of the value.
 */
enum cli_val_type cli_val_type(cli_val_t v);

/*
 * Returns alignment requirements of the value.
 */
size_t cli_val_alignof(cli_val_t v);

/*
 * Returns the size of the value.
 */
size_t cli_val_sizeof(cli_val_t v);

/*
 * Returns a pointer to the underlying data.
 *
 * The pointer can be dereferenced but you must be sure to know what you're
 * doing.
 */
void *cli_val_data(cli_val_t v);

/*
 * Adds the other value.
 */
int cli_val_add(cli_val_t v, cli_val_t other_v);

/*
 * Subtracts the other value.
 */
int cli_val_sub(cli_val_t v, cli_val_t other_v);

/*
 * Compares two values.
 *
 * Returns 0 if they're equal.
 * Returns 1 if the first is greater than the second.
 * Returns -1 if the first is less than the second.
 */
int cli_val_cmp(cli_val_t v, cli_val_t other_v);

/*
 * Attempts to write the value as text to a file.
 *
 * Returns how many characters were written.
 */
int cli_val_print(cli_val_t v, FILE *f);

/*
 * Attempts to read the value as text from a file.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_scan(cli_val_t v, FILE *f);

/*
 * Attempts to parse the value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_parse_text(cli_val_t v, const char *s);

/*
 * Attempts to interpret a value in its representation in binary from a stream
 * of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
int cli_val_parse_binary(cli_val_t v, const void *b, size_t length);

/*
 * Returns a value that represents no value. This will always return the same
 * value.
 *
 * Never pass it to a function otherwise the program will crash.
 */
cli_val_t cli_val_nil(void);

#endif /* CLI_VAL_H */

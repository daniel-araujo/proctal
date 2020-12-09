#ifndef CLI_VAL_ASSEMBLER_H
#define CLI_VAL_ASSEMBLER_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "cli/assembler/assembler.h"

/*
 * How our instruction values are represented in memory.
 */
struct cli_val_assembler {
	struct cli_assembler assembler;

	// Bytecode.
	char *bytecode;

	// Bytecode size.
	size_t bytecode_size;
};

/*
 * Creates an instruction value obeying the given attributes.
 *
 * By default no instruction is defined.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_assembler *cli_val_assembler_create(struct cli_assembler *assembler)
{
	struct cli_val_assembler *v = malloc(sizeof(*v));

	if (v == NULL) {
		return NULL;
	}

	v->assembler = *assembler;
	v->bytecode = NULL;
	v->bytecode_size = 0;

	return v;
}

/*
 * Destroys an instruction value created by a call to cli_val_assembler_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_assembler_destroy(struct cli_val_assembler *v)
{
	if (v->bytecode) {
		free(v->bytecode);
	}

	cli_assembler_deinit(&v->assembler);

	free(v);
}

/*
 * Sets the address the instruction would be executed at.
 */
inline void cli_val_assembler_address_set(struct cli_val_assembler *v, void *address)
{
	cli_assembler_address_set(&v->assembler, address);
}

/*
 * Returns the address that the instruction would be executed at.
 */
inline void *cli_val_assembler_address(struct cli_val_assembler *v)
{
	return cli_assembler_address(&v->assembler);
}

/*
 * Returns a pointer to the raw data that represents the instruction value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_assembler_data(struct cli_val_assembler *v)
{
	return v->bytecode;
}

/*
 * Size of the instruction value.
 */
inline size_t cli_val_assembler_sizeof(struct cli_val_assembler *v)
{
	return v->bytecode_size;
}

/*
 * Attempts to write the instruction value as text to a file.
 *
 * Returns how many characters were written.
 */
int cli_val_assembler_print(struct cli_val_assembler *v, FILE *f);

/*
 * Attempts to interpret an instruction value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
int cli_val_assembler_parse_binary(struct cli_val_assembler *v, const void *b, size_t length);

/*
 * Attempts to parse the instruction value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_assembler_parse_text(struct cli_val_assembler *v, const char *s);

/*
 * Creates a new instruction value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_assembler *cli_val_assembler_create_clone(struct cli_val_assembler *other_v)
{
	struct cli_val_assembler *v = cli_val_assembler_create(&other_v->assembler);

	if (v == NULL) {
		return NULL;
	}

	if (other_v->bytecode) {
		cli_val_assembler_parse_binary(v, other_v->bytecode, other_v->bytecode_size);
	}

	return v;
}

#endif /* CLI_VAL_ASSEMBLER_H */

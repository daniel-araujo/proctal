#ifndef CLI_VAL_SPARC_H
#define CLI_VAL_SPARC_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "cli/val/assembler.h"

/*
 * Modes.
 */
enum cli_val_sparc_mode {
	CLI_VAL_SPARC_MODE_32,
	CLI_VAL_SPARC_MODE_64,
	CLI_VAL_SPARC_MODE_V9,
};

/*
 * Endianness.
 */
enum cli_val_sparc_endianness {
	CLI_VAL_SPARC_ENDIANNESS_LITTLE,
	CLI_VAL_SPARC_ENDIANNESS_BIG,
};

/*
 * Attributes.
 */
struct cli_val_sparc_attr {
	enum cli_val_sparc_mode mode;
	enum cli_val_sparc_endianness endianness;
};

/*
 * Default attributes.
 */
#define CLI_VAL_SPARC_MODE_DEFAULT CLI_VAL_SPARC_MODE_64

#if PROCTAL_INTEGER_ENDIANNESS_LITTLE

	#define CLI_VAL_SPARC_ENDIANNESS_DEFAULT CLI_VAL_SPARC_ENDIANNESS_LITTLE

#elif PROCTAL_INTEGER_ENDIANNESS_BIG

	#define CLI_VAL_SPARC_ENDIANNESS_DEFAULT CLI_VAL_SPARC_ENDIANNESS_BIG

#endif

/*
 * The structure.
 */
struct cli_val_sparc {
	struct cli_val_assembler implementation;
};

/*
 * Sets the initial state of attributes.
 */
inline void cli_val_sparc_attr_init(struct cli_val_sparc_attr *a)
{
	a->mode = CLI_VAL_SPARC_MODE_DEFAULT;
	a->endianness = CLI_VAL_SPARC_ENDIANNESS_DEFAULT;
}

/*
 * Sets mode.
 */
inline void cli_val_sparc_attr_mode_set(struct cli_val_sparc_attr *a, enum cli_val_sparc_mode mode)
{
	a->mode = mode;
}

/*
 * Sets endianness.
 */
inline void cli_val_sparc_attr_endianness_set(struct cli_val_sparc_attr *a, enum cli_val_sparc_endianness endianness)
{
	a->endianness = endianness;
}

/*
 * Disposes attributes.
 */
inline void cli_val_sparc_attr_deinit(struct cli_val_sparc_attr *a)
{
}

/*
 * Creates an sparc instruction value.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_sparc *cli_val_sparc_create(struct cli_val_sparc_attr *a)
{
	struct cli_assembler assembler;
	cli_assembler_init(&assembler);
	cli_assembler_architecture_set(&assembler, CLI_ASSEMBLER_ARCHITECTURE_SPARC);

	switch (a->mode) {
	case CLI_VAL_SPARC_MODE_32:
		cli_assembler_sparc_mode_set(&assembler, CLI_ASSEMBLER_SPARC_MODE_32);
		break;

	case CLI_VAL_SPARC_MODE_64:
		cli_assembler_sparc_mode_set(&assembler, CLI_ASSEMBLER_SPARC_MODE_64);
		break;

	case CLI_VAL_SPARC_MODE_V9:
		cli_assembler_sparc_mode_set(&assembler, CLI_ASSEMBLER_SPARC_MODE_V9);
		break;

	default:
		// Not supported.
		cli_assembler_deinit(&assembler);
		return NULL;
	}

	switch (a->endianness) {
	case CLI_VAL_SPARC_ENDIANNESS_LITTLE:
		cli_assembler_endianness_set(&assembler, CLI_ASSEMBLER_ENDIANNESS_LITTLE);
		break;

	case CLI_VAL_SPARC_ENDIANNESS_BIG:
		cli_assembler_endianness_set(&assembler, CLI_ASSEMBLER_ENDIANNESS_BIG);
		break;

	default:
		// Not supported.
		cli_assembler_deinit(&assembler);
		return NULL;
	}

	struct cli_val_sparc *v = (struct cli_val_sparc *) cli_val_assembler_create(&assembler);

	cli_assembler_deinit(&assembler);

	return v;
}

/*
 * Destroys an instruction value created by a call to cli_val_sparc_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_sparc_destroy(struct cli_val_sparc *v)
{
	cli_val_assembler_destroy(&v->implementation);
}

/*
 * Sets the address the instruction would be executed at.
 */
inline void cli_val_sparc_address_set(struct cli_val_sparc *v, void *address)
{
	cli_val_assembler_address_set(&v->implementation, address);
}

/*
 * Returns the address that the instruction would be executed at.
 */
inline void *cli_val_sparc_address(struct cli_val_sparc *v)
{
	return cli_val_assembler_address(&v->implementation);
}

/*
 * Returns a pointer to the raw data that represents the instruction value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_sparc_data(struct cli_val_sparc *v)
{
	return cli_val_assembler_data(&v->implementation);
}

/*
 * Size of the instruction value.
 */
inline size_t cli_val_sparc_sizeof(struct cli_val_sparc *v)
{
	return cli_val_assembler_sizeof(&v->implementation);
}

/*
 * Attempts to write the instruction value as text to a file.
 *
 * Returns how many characters were written.
 */
inline int cli_val_sparc_print(struct cli_val_sparc *v, FILE *f)
{
	return cli_val_assembler_print(&v->implementation, f);
}

/*
 * Attempts to interpret an instruction value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_sparc_parse_binary(struct cli_val_sparc *v, const char *s, size_t length)
{
	return cli_val_assembler_parse_binary(&v->implementation, s, length);
}

/*
 * Attempts to parse the instruction value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
inline int cli_val_sparc_parse_text(struct cli_val_sparc *v, const char *s)
{
	return cli_val_assembler_parse_text(&v->implementation, s);
}

/*
 * Creates a new instruction value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_sparc *cli_val_sparc_create_clone(struct cli_val_sparc *other_v)
{
	return (struct cli_val_sparc *) cli_val_assembler_create_clone(&other_v->implementation);
}

#endif /* CLI_VAL_SPARC_H */

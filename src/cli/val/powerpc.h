#ifndef CLI_VAL_POWERPC_H
#define CLI_VAL_POWERPC_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "config.h"
#include "cli/val/assembler.h"

/*
 * Modes.
 */
enum cli_val_powerpc_mode {
	CLI_VAL_POWERPC_MODE_32,
	CLI_VAL_POWERPC_MODE_64,
	CLI_VAL_POWERPC_MODE_QPX,
};

/*
 * Endianness.
 */
enum cli_val_powerpc_endianness {
	CLI_VAL_POWERPC_ENDIANNESS_LITTLE,
	CLI_VAL_POWERPC_ENDIANNESS_BIG,
};

/*
 * Attributes.
 */
struct cli_val_powerpc_attr {
	enum cli_val_powerpc_mode mode;
	enum cli_val_powerpc_endianness endianness;
};

/*
 * Default attributes.
 */
#define CLI_VAL_POWERPC_MODE_DEFAULT CLI_VAL_POWERPC_MODE_64

#ifdef PROCTAL_INTEGER_ENDIANNESS_LITTLE

	#define CLI_VAL_POWERPC_ENDIANNESS_DEFAULT CLI_VAL_POWERPC_ENDIANNESS_LITTLE

#elif defined PROCTAL_INTEGER_ENDIANNESS_BIG

	#define CLI_VAL_POWERPC_ENDIANNESS_DEFAULT CLI_VAL_POWERPC_ENDIANNESS_BIG

#else

	#error "Unknown integer endianness."

#endif

/*
 * The structure.
 */
struct cli_val_powerpc {
	struct cli_val_assembler implementation;
};

/*
 * Sets the initial state of attributes.
 */
inline void cli_val_powerpc_attr_init(struct cli_val_powerpc_attr *a)
{
	a->mode = CLI_VAL_POWERPC_MODE_DEFAULT;
	a->endianness = CLI_VAL_POWERPC_ENDIANNESS_DEFAULT;
}

/*
 * Sets mode.
 */
inline void cli_val_powerpc_attr_mode_set(struct cli_val_powerpc_attr *a, enum cli_val_powerpc_mode mode)
{
	a->mode = mode;
}

/*
 * Sets endianness.
 */
inline void cli_val_powerpc_attr_endianness_set(struct cli_val_powerpc_attr *a, enum cli_val_powerpc_endianness endianness)
{
	a->endianness = endianness;
}

/*
 * Disposes attributes.
 */
inline void cli_val_powerpc_attr_deinit(struct cli_val_powerpc_attr *a)
{
}

/*
 * Creates an powerpc instruction value.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_powerpc *cli_val_powerpc_create(struct cli_val_powerpc_attr *a)
{
	struct cli_assembler assembler;
	cli_assembler_init(&assembler);
	cli_assembler_architecture_set(&assembler, CLI_ASSEMBLER_ARCHITECTURE_POWERPC);

	switch (a->mode) {
	case CLI_VAL_POWERPC_MODE_32:
		cli_assembler_powerpc_mode_set(&assembler, CLI_ASSEMBLER_POWERPC_MODE_32);
		break;

	case CLI_VAL_POWERPC_MODE_64:
		cli_assembler_powerpc_mode_set(&assembler, CLI_ASSEMBLER_POWERPC_MODE_64);
		break;

	case CLI_VAL_POWERPC_MODE_QPX:
		cli_assembler_powerpc_mode_set(&assembler, CLI_ASSEMBLER_POWERPC_MODE_QPX);
		break;

	default:
		// Not supported.
		cli_assembler_deinit(&assembler);
		return NULL;
	}

	switch (a->endianness) {
	case CLI_VAL_POWERPC_ENDIANNESS_LITTLE:
		cli_assembler_endianness_set(&assembler, CLI_ASSEMBLER_ENDIANNESS_LITTLE);
		break;

	case CLI_VAL_POWERPC_ENDIANNESS_BIG:
		cli_assembler_endianness_set(&assembler, CLI_ASSEMBLER_ENDIANNESS_BIG);
		break;

	default:
		// Not supported.
		cli_assembler_deinit(&assembler);
		return NULL;
	}

	struct cli_val_powerpc *v = (struct cli_val_powerpc *) cli_val_assembler_create(&assembler);

	cli_assembler_deinit(&assembler);

	return v;
}

/*
 * Destroys an instruction value created by a call to cli_val_powerpc_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_powerpc_destroy(struct cli_val_powerpc *v)
{
	cli_val_assembler_destroy(&v->implementation);
}

/*
 * Sets the address the instruction would be executed at.
 */
inline void cli_val_powerpc_address_set(struct cli_val_powerpc *v, void *address)
{
	cli_val_assembler_address_set(&v->implementation, address);
}

/*
 * Returns the address that the instruction would be executed at.
 */
inline void *cli_val_powerpc_address(struct cli_val_powerpc *v)
{
	return cli_val_assembler_address(&v->implementation);
}

/*
 * Returns a pointer to the raw data that represents the instruction value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_powerpc_data(struct cli_val_powerpc *v)
{
	return cli_val_assembler_data(&v->implementation);
}

/*
 * Size of the instruction value.
 */
inline size_t cli_val_powerpc_sizeof(struct cli_val_powerpc *v)
{
	return cli_val_assembler_sizeof(&v->implementation);
}

/*
 * Attempts to write the instruction value as text to a file.
 *
 * Returns how many characters were written.
 */
inline int cli_val_powerpc_print(struct cli_val_powerpc *v, FILE *f)
{
	return cli_val_assembler_print(&v->implementation, f);
}

/*
 * Attempts to interpret an instruction value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_powerpc_parse_binary(struct cli_val_powerpc *v, const void *b, size_t length)
{
	return cli_val_assembler_parse_binary(&v->implementation, b, length);
}

/*
 * Attempts to parse the instruction value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
inline int cli_val_powerpc_parse_text(struct cli_val_powerpc *v, const char *s)
{
	return cli_val_assembler_parse_text(&v->implementation, s);
}

/*
 * Creates a new instruction value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_powerpc *cli_val_powerpc_create_clone(struct cli_val_powerpc *other_v)
{
	return (struct cli_val_powerpc *) cli_val_assembler_create_clone(&other_v->implementation);
}

#endif /* CLI_VAL_POWERPC_H */

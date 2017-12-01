#ifndef CLI_VAL_X86_H
#define CLI_VAL_X86_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "cli/val/assembler.h"

/*
 * Modes.
 */
enum cli_val_x86_mode {
	CLI_VAL_X86_MODE_16,
	CLI_VAL_X86_MODE_32,
	CLI_VAL_X86_MODE_64,
};

/*
 * Syntaxes.
 */
enum cli_val_x86_syntax {
	CLI_VAL_X86_SYNTAX_INTEL,
	CLI_VAL_X86_SYNTAX_ATT,
};

/*
 * Describes the behavior of the instruction value.
 */
struct cli_val_x86_attr {
	enum cli_val_x86_mode mode;
	enum cli_val_x86_syntax syntax;
};

#define CLI_VAL_X86_MODE_DEFAULT CLI_VAL_X86_MODE_64
#define CLI_VAL_X86_SYNTAX_DEFAULT CLI_VAL_X86_SYNTAX_INTEL

/*
 * The structure.
 */
struct cli_val_x86 {
	struct cli_val_assembler implementation;
};

/*
 * Sets the initial state of attributes.
 */
inline void cli_val_x86_attr_init(struct cli_val_x86_attr *a)
{
	a->mode = CLI_VAL_X86_MODE_DEFAULT;
	a->syntax = CLI_VAL_X86_SYNTAX_DEFAULT;
}

/*
 * Sets mode.
 */
inline void cli_val_x86_attr_mode_set(struct cli_val_x86_attr *a, enum cli_val_x86_mode mode)
{
	a->mode = mode;
}

/*
 * Sets syntax.
 */
inline void cli_val_x86_attr_syntax_set(struct cli_val_x86_attr *a, enum cli_val_x86_syntax syntax)
{
	a->syntax = syntax;
}

/*
 * Disposes attributes.
 */
inline void cli_val_x86_attr_deinit(struct cli_val_x86_attr *a)
{
}

/*
 * Creates an x86 instruction value.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_x86 *cli_val_x86_create(struct cli_val_x86_attr *a)
{
	struct cli_assembler assembler;
	cli_assembler_init(&assembler);

	switch (a->mode) {
	case CLI_VAL_X86_MODE_16:
		cli_assembler_architecture_set(&assembler, CLI_ASSEMBLER_ARCHITECTURE_X86);
		cli_assembler_x86_mode_set(&assembler, CLI_ASSEMBLER_X86_MODE_16);
		break;

	case CLI_VAL_X86_MODE_32:
		cli_assembler_architecture_set(&assembler, CLI_ASSEMBLER_ARCHITECTURE_X86);
		cli_assembler_x86_mode_set(&assembler, CLI_ASSEMBLER_X86_MODE_32);
		break;

	case CLI_VAL_X86_MODE_64:
		cli_assembler_architecture_set(&assembler, CLI_ASSEMBLER_ARCHITECTURE_X86);
		cli_assembler_x86_mode_set(&assembler, CLI_ASSEMBLER_X86_MODE_64);
		break;

	default:
		// Not supported.
		cli_assembler_deinit(&assembler);
		return NULL;
	}

	switch (a->syntax) {
	case CLI_VAL_X86_SYNTAX_INTEL:
		cli_assembler_x86_syntax_set(&assembler, CLI_ASSEMBLER_X86_SYNTAX_INTEL);
		break;

	case CLI_VAL_X86_SYNTAX_ATT:
		cli_assembler_x86_syntax_set(&assembler, CLI_ASSEMBLER_X86_SYNTAX_ATT);
		break;

	default:
		// Not supported.
		cli_assembler_deinit(&assembler);
		return NULL;
	}

	struct cli_val_x86 *v = (struct cli_val_x86 *) cli_val_assembler_create(&assembler);

	cli_assembler_deinit(&assembler);

	return v;
}

/*
 * Destroys an instruction value created by a call to cli_val_x86_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_x86_destroy(struct cli_val_x86 *v)
{
	cli_val_assembler_destroy(&v->implementation);
}

/*
 * Sets the address the instruction would be executed at.
 */
inline void cli_val_x86_address_set(struct cli_val_x86 *v, void *address)
{
	cli_val_assembler_address_set(&v->implementation, address);
}

/*
 * Returns the address that the instruction would be executed at.
 */
inline void *cli_val_x86_address(struct cli_val_x86 *v)
{
	return cli_val_assembler_address(&v->implementation);
}

/*
 * Returns a pointer to the raw data that represents the instruction value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_x86_data(struct cli_val_x86 *v)
{
	return cli_val_assembler_data(&v->implementation);
}

/*
 * Size of the instruction value.
 */
inline size_t cli_val_x86_sizeof(struct cli_val_x86 *v)
{
	return cli_val_assembler_sizeof(&v->implementation);
}

/*
 * Attempts to write the instruction value as text to a file.
 *
 * Returns how many characters were written.
 */
inline int cli_val_x86_print(struct cli_val_x86 *v, FILE *f)
{
	return cli_val_assembler_print(&v->implementation, f);
}

/*
 * Attempts to interpret an instruction value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_x86_parse_binary(struct cli_val_x86 *v, const void *b, size_t length)
{
	return cli_val_assembler_parse_binary(&v->implementation, b, length);
}

/*
 * Attempts to parse the instruction value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
inline int cli_val_x86_parse_text(struct cli_val_x86 *v, const char *s)
{
	return cli_val_assembler_parse_text(&v->implementation, s);
}

/*
 * Creates a new instruction value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_x86 *cli_val_x86_create_clone(struct cli_val_x86 *other_v)
{
	return (struct cli_val_x86 *) cli_val_assembler_create_clone(&other_v->implementation);
}

#endif /* CLI_VAL_X86_H */

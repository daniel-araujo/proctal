#ifndef CLI_VAL_ARM_H
#define CLI_VAL_ARM_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "cli/val/assembler.h"

/*
 * Describes the behavior of the instruction value.
 */
struct cli_val_arm_attr {};

/*
 * The structure.
 */
struct cli_val_arm {
	struct cli_val_assembler implementation;
};

/*
 * Sets the initial state of instruction value attributes.
 */
inline void cli_val_arm_attr_init(struct cli_val_arm_attr *a)
{
}

/*
 * Disposes attributes.
 */
inline void cli_val_arm_attr_deinit(struct cli_val_arm_attr *a)
{
}

/*
 * Creates an arm instruction value.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_arm *cli_val_arm_create(struct cli_val_arm_attr *a)
{
	struct cli_assembler assembler;
	cli_assembler_init(&assembler);
	cli_assembler_architecture_set(&assembler, CLI_ASSEMBLER_ARCHITECTURE_ARM);

	return (struct cli_val_arm *) cli_val_assembler_create(&assembler);
}

/*
 * Destroys an instruction value created by a call to cli_val_arm_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_arm_destroy(struct cli_val_arm *v)
{
	cli_val_assembler_destroy(&v->implementation);
}

/*
 * Sets the address the instruction would be executed at.
 */
inline void cli_val_arm_address_set(struct cli_val_arm *v, void *address)
{
	cli_val_assembler_address_set(&v->implementation, address);
}

/*
 * Returns the address that the instruction would be executed at.
 */
inline void *cli_val_arm_address(struct cli_val_arm *v)
{
	return cli_val_assembler_address(&v->implementation);
}

/*
 * Returns a pointer to the raw data that represents the instruction value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_arm_data(struct cli_val_arm *v)
{
	return cli_val_assembler_data(&v->implementation);
}

/*
 * Size of the instruction value.
 */
inline size_t cli_val_arm_sizeof(struct cli_val_arm *v)
{
	return cli_val_assembler_sizeof(&v->implementation);
}

/*
 * Attempts to write the instruction value as text to a file.
 *
 * Returns how many characters were written.
 */
inline int cli_val_arm_print(struct cli_val_arm *v, FILE *f)
{
	return cli_val_assembler_print(&v->implementation, f);
}

/*
 * Attempts to interpret an instruction value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_arm_parse_binary(struct cli_val_arm *v, const char *s, size_t length)
{
	return cli_val_assembler_parse_binary(&v->implementation, s, length);
}

/*
 * Attempts to parse the instruction value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
inline int cli_val_arm_parse_text(struct cli_val_arm *v, const char *s)
{
	return cli_val_assembler_parse_text(&v->implementation, s);
}

/*
 * Creates a new instruction value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_arm *cli_val_arm_create_clone(struct cli_val_arm *other_v)
{
	return (struct cli_val_arm *) cli_val_assembler_create_clone(&other_v->implementation);
}

#endif /* CLI_VAL_ARM_H */

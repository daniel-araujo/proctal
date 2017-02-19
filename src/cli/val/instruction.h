#ifndef CLI_VAL_INSTRUCTION_H
#define CLI_VAL_INSTRUCTION_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

/*
 * Supported architectures.
 */
enum cli_val_instruction_arch {
	CLI_VAL_INSTRUCTION_ARCH_X86_64,
};

/*
 * Describes the behavior of an instruction value.
 */
struct cli_val_instruction_attr {
	enum cli_val_instruction_arch arch;
};

/*
 * How our instruction values are represented in memory.
 */
struct cli_val_instruction {
	// Describes the behavior of the instruction.
	struct cli_val_instruction_attr attr;

	// Address where the instruction would be at. This information is
	// important when calculating the destination address of a relative
	// jump instruction supported by certain architectures.
	void *addr;

	// Information about the instruction. We'll use capstone's parse
	// result.
	cs_insn *insn;
};

/*
 * Sets the initial state of instruction value attributes.
 */
inline void cli_val_instruction_attr_init(struct cli_val_instruction_attr *a)
{
	a->arch = CLI_VAL_INSTRUCTION_ARCH_X86_64;
}

/*
 * Sets architecture.
 */
inline void cli_val_instruction_attr_set_arch(
	struct cli_val_instruction_attr *a,
	enum cli_val_instruction_arch arch)
{
	a->arch = arch;
}

/*
 * Disposes it off.
 */
inline void cli_val_instruction_attr_deinit(struct cli_val_instruction_attr *a)
{
}

/*
 * Creates an instruction value obeying the given attributes.
 *
 * By default no instruction is defined.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_instruction *cli_val_instruction_create(struct cli_val_instruction_attr *a)
{
	struct cli_val_instruction *v = malloc(sizeof(*v));

	if (v == NULL) {
		return NULL;
	}

	v->attr = *a;
	v->addr = NULL;
	v->insn = NULL;

	return v;
}

/*
 * Destroys an instruction value created by a call to cli_val_instruction_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_instruction_destroy(struct cli_val_instruction *v)
{
	if (v->insn) {
		cs_free(v->insn, 1);
	}

	free(v);
}

/*
 * Sets the address the instruction would be placed at.
 */
inline void cli_val_instruction_set_address(struct cli_val_instruction *v, void *addr)
{
	v->addr = addr;
}

/*
 * Returns a pointer to the raw data that represents the instruction value.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_instruction_raw(struct cli_val_instruction *v)
{
	return v->insn->bytes;
}

/*
 * Size of the instruction value.
 */
inline size_t cli_val_instruction_sizeof(struct cli_val_instruction *v)
{
	if (v->insn == NULL) {
		return 0;
	}

	return v->insn->size;
}

/*
 * Attempts to write the instruction value as text to a file.
 *
 * Returns how many characters were written.
 */
inline int cli_val_instruction_print(struct cli_val_instruction *v, FILE *f)
{
	if (v->insn == NULL) {
		return 0;
	}

	int written = fprintf(f, "%s", v->insn->mnemonic);

	if (*v->insn->op_str) {
		written += fprintf(f, "\t%s", v->insn->op_str);
	}

	return written;
}

/*
 * Attempts to interpret an instruction value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
int cli_val_instruction_parse_bin(struct cli_val_instruction *v, const char *s, size_t length);

/*
 * Attempts to parse the instruction value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
int cli_val_instruction_parse(struct cli_val_instruction *v, const char *s);

/*
 * Creates a new instruction value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_instruction *cli_val_instruction_create_clone(struct cli_val_instruction *other_v)
{
	struct cli_val_instruction *v = cli_val_instruction_create(&other_v->attr);

	if (v == NULL) {
		return NULL;
	}

	cli_val_instruction_parse_bin(v, (const char *) other_v->insn->bytes, cli_val_instruction_sizeof(v));

	return v;
}

#endif /* CLI_VAL_INSTRUCTION_H */

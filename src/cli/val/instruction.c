#include "cli/val/instruction.h"

static void setup_assembler(struct cli_val_instruction *v, struct cli_assembler *assembler)
{
	switch (v->attr.arch) {
	case CLI_VAL_INSTRUCTION_ARCHITECTURE_X86:
		cli_assembler_arch_set(assembler, CLI_ASSEMBLER_ARCH_X86);
		break;

	case CLI_VAL_INSTRUCTION_ARCHITECTURE_X86_64:
		cli_assembler_arch_set(assembler, CLI_ASSEMBLER_ARCH_X86_64);
		break;

	case CLI_VAL_INSTRUCTION_ARCHITECTURE_ARM:
		cli_assembler_arch_set(assembler, CLI_ASSEMBLER_ARCH_ARM);
		break;

	case CLI_VAL_INSTRUCTION_ARCHITECTURE_AARCH64:
		cli_assembler_arch_set(assembler, CLI_ASSEMBLER_ARCH_AARCH64);
		break;
	}

	switch (v->attr.syntax) {
	case CLI_VAL_INSTRUCTION_SYNTAX_INTEL:
		cli_assembler_syntax_set(assembler, CLI_ASSEMBLER_SYNTAX_INTEL);
		break;

	case CLI_VAL_INSTRUCTION_SYNTAX_ATT:
		cli_assembler_syntax_set(assembler, CLI_ASSEMBLER_SYNTAX_ATT);
		break;
	}
}

void cli_val_instruction_attr_init(struct cli_val_instruction_attr *a);

void cli_val_instruction_attr_arch_set(
	struct cli_val_instruction_attr *a,
	enum cli_val_instruction_architecture arch);

void cli_val_instruction_attr_syntax_set(
	struct cli_val_instruction_attr *a,
	enum cli_val_instruction_syntax syntax);

void cli_val_instruction_attr_deinit(struct cli_val_instruction_attr *a);

struct cli_val_instruction *cli_val_instruction_create(struct cli_val_instruction_attr *a);

void cli_val_instruction_destroy(struct cli_val_instruction *v);

void cli_val_instruction_address_set(struct cli_val_instruction *v, void *address);

void *cli_val_instruction_address(struct cli_val_instruction *v);

void *cli_val_instruction_data(struct cli_val_instruction *v);

size_t cli_val_instruction_sizeof(struct cli_val_instruction *v);

struct cli_val_instruction *cli_val_instruction_create_clone(struct cli_val_instruction *other_v);

int cli_val_instruction_print(struct cli_val_instruction *v, FILE *f)
{
	int ret = 0;

	if (v->bytecode_size == 0) {
		return 0;
	}

	struct cli_assembler assembler;
	cli_assembler_init(&assembler);
	setup_assembler(v, &assembler);
	cli_assembler_address_set(&assembler, v->address);

	struct cli_assembler_decompile_result result;
	if (!cli_assembler_decompile(&assembler, v->bytecode, v->bytecode_size, &result)) {
		goto exit1;
	}

	ret = fwrite(result.assembly, result.assembly_size, 1, f);

exit2:
	cli_assembler_decompile_dispose(&result);
exit1:
	cli_assembler_deinit(&assembler);
exit0:
	return ret;
}

int cli_val_instruction_parse_binary(struct cli_val_instruction *v, const char *s, size_t length)
{
	int ret = 0;

	// We're going to decompile the bytecode to see if it is a valid
	// instruction and exactly how long.

	struct cli_assembler assembler;
	cli_assembler_init(&assembler);
	setup_assembler(v, &assembler);
	cli_assembler_address_set(&assembler, v->address);

	struct cli_assembler_decompile_result result;
	if (!cli_assembler_decompile(&assembler, s, length, &result)) {
		goto exit1;
	}

	// At this point we know that we got valid bytecode and how long it is.
	// Let's make a copy of it and return how much we read.

	char *bytecode = malloc(result.read);

	if (bytecode == NULL) {
		goto exit2;
	}

	memcpy(bytecode, s, result.read);

	if (v->bytecode) {
		// Discard the existing bytecode.
		free(v->bytecode);
	}

	v->bytecode = bytecode;
	v->bytecode_size = result.read;

	ret = result.read;
exit2:
	cli_assembler_decompile_dispose(&result);
exit1:
	cli_assembler_deinit(&assembler);
exit0:
	return ret;
}

int cli_val_instruction_parse_text(struct cli_val_instruction *v, const char *s)
{
	int ret = 0;

	struct cli_assembler assembler;
	cli_assembler_init(&assembler);
	setup_assembler(v, &assembler);
	cli_assembler_address_set(&assembler, v->address);

	struct cli_assembler_compile_result result;
	if (!cli_assembler_compile(&assembler, s, strlen(s), &result)) {
		goto exit1;
	}

	char *bytecode = malloc(result.bytecode_size);

	if (bytecode == NULL) {
		goto exit2;
	}

	memcpy(bytecode, result.bytecode, result.bytecode_size);

	if (v->bytecode) {
		// Discard the existing bytecode.
		free(v->bytecode);
	}

	v->bytecode = bytecode;
	v->bytecode_size = result.bytecode_size;

	ret = 1;
exit2:
	cli_assembler_compile_dispose(&result);
exit1:
	cli_assembler_deinit(&assembler);
exit0:
	return ret;
}

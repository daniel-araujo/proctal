#include "cli/val/assembler.h"

extern inline struct cli_val_assembler *cli_val_assembler_create(struct cli_assembler *assembler);

extern inline void cli_val_assembler_destroy(struct cli_val_assembler *v);

extern inline void cli_val_assembler_address_set(struct cli_val_assembler *v, void *address);

extern inline void *cli_val_assembler_address(struct cli_val_assembler *v);

extern inline void *cli_val_assembler_data(struct cli_val_assembler *v);

extern inline size_t cli_val_assembler_sizeof(struct cli_val_assembler *v);

extern inline struct cli_val_assembler *cli_val_assembler_create_clone(struct cli_val_assembler *other_v);

int cli_val_assembler_print(struct cli_val_assembler *v, FILE *f)
{
	int ret = 0;

	if (v->bytecode_size == 0) {
		return 0;
	}

	struct cli_assembler_decompile_result result;
	if (!cli_assembler_decompile(&v->assembler, v->bytecode, v->bytecode_size, &result)) {
		goto exit0;
	}

	ret = fwrite(result.assembly, result.assembly_size, 1, f);
exit1:
	cli_assembler_decompile_dispose(&result);
exit0:
	return ret;
}

int cli_val_assembler_parse_binary(struct cli_val_assembler *v, const char *s, size_t length)
{
	int ret = 0;

	// We're going to decompile the bytecode to see if it is a valid
	// instruction and exactly how long it is.

	struct cli_assembler_decompile_result result;
	if (!cli_assembler_decompile(&v->assembler, s, length, &result)) {
		goto exit0;
	}

	// At this point we know that we got valid bytecode and how long it is.
	// Let's make a copy of it and return how much we read.

	char *bytecode = malloc(result.read);

	if (bytecode == NULL) {
		goto exit1;
	}

	memcpy(bytecode, s, result.read);

	if (v->bytecode) {
		// Discard the existing bytecode.
		free(v->bytecode);
	}

	v->bytecode = bytecode;
	v->bytecode_size = result.read;

	ret = result.read;
exit1:
	cli_assembler_decompile_dispose(&result);
exit0:
	return ret;
}

int cli_val_assembler_parse_text(struct cli_val_assembler *v, const char *s)
{
	int ret = 0;

	struct cli_assembler_compile_result result;
	if (!cli_assembler_compile(&v->assembler, s, strlen(s), &result)) {
		goto exit0;
	}

	char *bytecode = malloc(result.bytecode_size);

	if (bytecode == NULL) {
		goto exit1;
	}

	memcpy(bytecode, result.bytecode, result.bytecode_size);

	if (v->bytecode) {
		// Discard the existing bytecode.
		free(v->bytecode);
	}

	v->bytecode = bytecode;
	v->bytecode_size = result.bytecode_size;

	ret = 1;
exit1:
	cli_assembler_compile_dispose(&result);
exit0:
	return ret;
}

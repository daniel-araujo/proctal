#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "cli/assembler.h"
#include "cli/assembler/implementation.h"

void cli_assembler_init(struct cli_assembler *assembler);

void cli_assembler_deinit(struct cli_assembler *assembler);

void cli_assembler_arch_set(struct cli_assembler *assembler, enum cli_assembler_arch arch);

void cli_assembler_syntax_set(struct cli_assembler *assembler, enum cli_assembler_syntax syntax);

void cli_assembler_address_set(struct cli_assembler *assembler, void *address);

const char *cli_assembler_error_message(struct cli_assembler *assembler);

int cli_assembler_compile(struct cli_assembler *assembler, const char *assembly, size_t assembly_size, struct cli_assembler_compile_result *result)
{
	return cli_assembler_implementation_compile(assembler, assembly, assembly_size, result);
}

void cli_assembler_compile_dispose(struct cli_assembler_compile_result *result)
{
	cli_assembler_implementation_compile_dispose(result);
}

int cli_assembler_decompile(struct cli_assembler *assembler, const char *bytecode, size_t bytecode_size, struct cli_assembler_decompile_result *result)
{
	return cli_assembler_implementation_decompile(assembler, bytecode, bytecode_size, result);
}

void cli_assembler_decompile_dispose(struct cli_assembler_decompile_result *result)
{
	cli_assembler_implementation_decompile_dispose(result);
}

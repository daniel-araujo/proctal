#include "cli/assembler/internal.h"
#include "cli/assembler/implementation.h"

int cli_assembler_implementation_decompile(struct cli_assembler *assembler, const char *bytecode, size_t bytecode_size, struct cli_assembler_decompile_result *result)
{
	cli_assembler_error_message_set(assembler, "This feature is not available because Proctal was not compiled with support for Capstone.");

	return 0;
}

void cli_assembler_implementation_decompile_dispose(struct cli_assembler_decompile_result *result)
{
}

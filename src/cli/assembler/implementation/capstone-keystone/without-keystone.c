#include "cli/assembler/internal.h"
#include "cli/assembler/implementation.h"

int cli_assembler_implementation_compile(struct cli_assembler *assembler, const char *assembly, size_t assembly_size, struct cli_assembler_compile_result *result)
{
	cli_assembler_error_message_set(assembler, "This feature is not available because Proctal was not compiled with support for Keystone.");

	return 0;
}

void cli_assembler_implementation_compile_dispose(struct cli_assembler_compile_result *result)
{
}

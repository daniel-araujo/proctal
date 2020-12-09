#include "cli/assembler/internal.h"
#include "cli/parser/parser.h"

void cli_assembler_error_message_set(struct cli_assembler *assembler, const char *message)
{
	assembler->error_message = message;
}

size_t cli_assembler_limit_to_one_instruction(const char *assembly, size_t assembly_size)
{
	if (assembly_size == 0) {
		return 0;
	}

	return cli_parse_skip_until_chars2(assembly, assembly_size, "\n;");
}

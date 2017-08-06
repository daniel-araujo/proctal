#ifndef CLI_ASSEMBLER_INTERNAL_H
#define CLI_ASSEMBLER_INTERNAL_H

#include "cli/assembler.h"

void cli_assembler_error_message_set(struct cli_assembler *assembler, const char *message);

size_t cli_assembler_limit_to_one_instruction(const char *assembly, size_t assembly_size);

#endif /* CLI_ASSEMBLER_INTERNAL_H */

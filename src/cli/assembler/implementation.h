#ifndef CLI_ASSEMBLER_IMPLEMENTATION_H
#define CLI_ASSEMBLER_IMPLEMENTATION_H

#include "cli/assembler/assembler.h"

int cli_assembler_implementation_decompile(struct cli_assembler *assembler, const char *bytecode, size_t bytecode_size, struct cli_assembler_decompile_result *result);

void cli_assembler_implementation_decompile_dispose(struct cli_assembler_decompile_result *result);

int cli_assembler_implementation_compile(struct cli_assembler *assembler, const char *assembly, size_t assembly_size, struct cli_assembler_compile_result *result);

void cli_assembler_implementation_compile_dispose(struct cli_assembler_compile_result *result);

#endif /* CLI_ASSEMBLER_IMPLEMENTATION_H */

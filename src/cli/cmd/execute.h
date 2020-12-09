#ifndef CLI_CMD_EXECUTE_H
#define CLI_CMD_EXECUTE_H

#include "cli/assembler/assembler.h"

enum cli_cmd_execute_format {
	CLI_CMD_EXECUTE_FORMAT_ASSEMBLY,
	CLI_CMD_EXECUTE_FORMAT_BYTECODE,
};

struct cli_cmd_execute_arg {
	int pid;

	// What format we're expecting the input to be.
	enum cli_cmd_execute_format format;

	// Architecture.
	enum cli_assembler_architecture architecture;

	// Endianness.
	enum cli_assembler_endianness endianness;

	// x86 mode.
	enum cli_assembler_x86_mode x86_mode;

	// x86 syntax.
	enum cli_assembler_x86_syntax x86_syntax;

	// ARM mode.
	enum cli_assembler_arm_mode arm_mode;

	// Sparc mode.
	enum cli_assembler_sparc_mode sparc_mode;

	// PowerPC mode.
	enum cli_assembler_powerpc_mode powerpc_mode;

	// Mips mode.
	enum cli_assembler_mips_mode mips_mode;
};

int cli_cmd_execute(struct cli_cmd_execute_arg *arg);

#endif /* CLI_CMD_EXECUTE_H */

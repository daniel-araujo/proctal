#ifndef CLI_CMD_EXECUTE_H
#define CLI_CMD_EXECUTE_H

#include "cli/assembler.h"

enum cli_cmd_execute_format {
	CLI_CMD_EXECUTE_FORMAT_ASSEMBLY,
	CLI_CMD_EXECUTE_FORMAT_BYTECODE,
};

struct cli_cmd_execute_arg {
	int pid;

	// What format we're expecting the input to be.
	enum cli_cmd_execute_format format;

	// Assembly architecture.
	enum cli_assembler_architecture architecture;

	// Assembly syntax.
	enum cli_assembler_x86_mode x86_mode;

	// Assembly syntax.
	enum cli_assembler_x86_syntax x86_syntax;
};

int cli_cmd_execute(struct cli_cmd_execute_arg *arg);

#endif /* CLI_CMD_EXECUTE_H */

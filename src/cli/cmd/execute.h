#ifndef CLI_CMD_EXECUTE_H
#define CLI_CMD_EXECUTE_H

enum cli_cmd_execute_format {
	CLI_CMD_EXECUTE_FORMAT_ASSEMBLY,
	CLI_CMD_EXECUTE_FORMAT_BYTECODE,
};

struct cli_cmd_execute_arg {
	int pid;

	// What format we're expecting the input to be.
	enum cli_cmd_execute_format format;
};

int cli_cmd_execute(struct cli_cmd_execute_arg *arg);

#endif /* CLI_CMD_EXECUTE_H */

#ifndef CLI_CMD_FREEZE_H
#define CLI_CMD_FREEZE_H

struct cli_cmd_freeze_arg {
	int pid;

	// Whether to quit when no more input is available.
	int input;
};

int cli_cmd_freeze(struct cli_cmd_freeze_arg *arg);

#endif /* CLI_CMD_FREEZE_H */

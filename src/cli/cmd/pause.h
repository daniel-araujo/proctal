#ifndef CLI_CMD_PAUSE_H
#define CLI_CMD_PAUSE_H

struct cli_cmd_pause_arg {
	int pid;
};

int cli_cmd_pause(struct cli_cmd_pause_arg *arg);

#endif /* CLI_CMD_PAUSE_H */

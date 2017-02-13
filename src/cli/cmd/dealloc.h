#ifndef CLI_CMD_DEALLOC_H
#define CLI_CMD_DEALLOC_H

struct cli_cmd_dealloc_arg {
	int pid;

	void *address;
};

int cli_cmd_dealloc(struct cli_cmd_dealloc_arg *arg);

#endif /* CLI_CMD_DEALLOC_H */

#ifndef CLI_CMD_DEALLOCATE_H
#define CLI_CMD_DEALLOCATE_H

struct cli_cmd_deallocate_arg {
	int pid;

	void *address;
};

int cli_cmd_deallocate(struct cli_cmd_deallocate_arg *arg);

#endif /* CLI_CMD_DEALLOCATE_H */

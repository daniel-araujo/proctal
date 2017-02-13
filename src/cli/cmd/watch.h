#ifndef CLI_CMD_WATCH_H
#define CLI_CMD_WATCH_H

struct cli_cmd_watch_arg {
	int pid;

	void *address;

	// Whether to watch for reads.
	int read;

	// Whether to watch for writes.
	int write;

	// Whether to watch for instruction execution.
	int execute;

	// Whether to print an address only once.
	int unique;
};

int cli_cmd_watch(struct cli_cmd_watch_arg *arg);

#endif /* CLI_CMD_WATCH_H */

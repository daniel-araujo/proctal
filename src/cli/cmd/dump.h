#ifndef CLI_CMD_DUMP_H
#define CLI_CMD_DUMP_H

struct cli_cmd_dump_arg {
	int pid;

	// Where to start dumping. Pass NULL to ignore this.
	void *address_start;

	// Where to stop dumping. Pass NULL to ignore this.
	void *address_stop;

	// Regions to search. Set to 0 to search all. Choose regions by using
	// macros that start with PROCTAL_REGION.
	int region;

	// Whether to dump readable memory addresses.
	int read;

	// Whether to dump writable memory addresses.
	int write;

	// Whether to dump executable memory addresses.
	int execute;

	// Whether to keep the program paused while dumping.
	int pause;
};

int cli_cmd_dump(struct cli_cmd_dump_arg *arg);

#endif /* CLI_CMD_DUMP_H */

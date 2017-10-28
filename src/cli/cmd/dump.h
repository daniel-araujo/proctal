#ifndef CLI_CMD_DUMP_H
#define CLI_CMD_DUMP_H

struct cli_cmd_dump_arg {
	int pid;

	// Where to start dumping. Pass NULL to ignore this.
	void *address_start;

	// Where to stop dumping. Pass NULL to ignore this.
	void *address_stop;

	// Whether to dump readable memory addresses.
	int read;

	// Whether to dump writable memory addresses.
	int write;

	// Whether to dump executable memory addresses.
	int execute;

	// Whether to dump program code.
	int program_code;

	// Whether to keep the program frozen while dumping.
	int freeze;
};

int cli_cmd_dump(struct cli_cmd_dump_arg *arg);

#endif /* CLI_CMD_DUMP_H */

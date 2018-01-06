#ifndef CLI_CMD_PATTERN_H
#define CLI_CMD_PATTERN_H

struct cli_cmd_pattern_arg {
	int pid;

	const char *pattern;

	// If not NULL, start searching from this address.
	void *address_start;

	// If not NULL, search up to this address.
	void *address_stop;

	// Regions to search. Set to 0 to search all. Choose regions by using
	// macros that start with PROCTAL_REGION.
	int region;

	// Whether to search readable memory addresses.
	int read;

	// Whether to search writable memory addresses.
	int write;

	// Whether to search executable memory addresses.
	int execute;

	// Whether to keep the program paused while searching.
	int pause;
};

int cli_cmd_pattern(struct cli_cmd_pattern_arg *arg);

#endif /* CLI_CMD_PATTERN_H */

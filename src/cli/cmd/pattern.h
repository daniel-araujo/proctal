#ifndef CLI_CMD_PATTERN_H
#define CLI_CMD_PATTERN_H

struct cli_cmd_pattern_arg {
	int pid;

	const char *pattern;

	// Whether to quit when no more input is available.
	int input;

	// Whether to search readable memory addresses.
	int read;

	// Whether to search writable memory addresses.
	int write;

	// Whether to search executable memory addresses.
	int execute;

	// Whether to search program code.
	int program_code;

	// Whether to keep the program frozen while searching.
	int freeze;
};

int cli_cmd_pattern(struct cli_cmd_pattern_arg *arg);

#endif /* CLI_CMD_PATTERN_H */

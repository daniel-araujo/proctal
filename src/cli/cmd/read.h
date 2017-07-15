#ifndef CLI_CMD_READ_H
#define CLI_CMD_READ_H

#include "cli/val.h"

struct cli_cmd_read_arg {
	int pid;

	void *address;

	// Number of values expected to read.
	size_t array;

	// How we're going to interpret values.
	cli_val value;

	// Whether to additionally print the value's address. Useful when
	// printing a lot of adjacent values of variable length.
	int show_address;

	// Whether to additionally print the bytecode of the instruction.
	int show_instruction_byte_code;
};

int cli_cmd_read(struct cli_cmd_read_arg *arg);

#endif /* CLI_CMD_READ_H */

#ifndef CLI_CMD_READ_H
#define CLI_CMD_READ_H

#include "cli/val.h"

struct cli_cmd_read_arg {
	int pid;

	void *address;

	// Number of values expected to read.
	size_t array;

	// How we're going to interpret values.
	cli_val_t value;

	// Whether to additionally print the value's address. Useful when
	// printing a lot of adjacent values of variable length.
	int show_address;

	// Additionally prints a sequence of numbers in hexadecimal that
	// represent the bytes of the value in memory.
	int show_bytes;

	// Whether to print exactly what's in memory.
	int binary;

	// Whether to keep the program frozen while reading.
	int freeze;
};

int cli_cmd_read(struct cli_cmd_read_arg *arg);

#endif /* CLI_CMD_READ_H */

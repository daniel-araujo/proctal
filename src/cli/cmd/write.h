#ifndef CLI_CMD_WRITE_H
#define CLI_CMD_WRITE_H

#include "cli/val-list.h"

struct cli_cmd_write_arg {
	int pid;

	void *address;

	// Number of values expected to write.
	size_t array;

	// List of values to write.
	cli_val_list value_list;

	// Whether to write the same value repeatedly until the program is told
	// to shut down.
	int repeat;
	// A delay in milliseconds before writing to the address again. Without
	// a delay you could theoretically turn your CPU into a heater.
	int repeat_delay;

	// Whether to keep the program frozen while writing.
	int freeze;
};

int cli_cmd_write(struct cli_cmd_write_arg *arg);

#endif /* CLI_CMD_WRITE_H */

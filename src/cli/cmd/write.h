#ifndef CLI_CMD_WRITE_H
#define CLI_CMD_WRITE_H

#include <darr.h>

#include "cli/val.h"

struct cli_cmd_write_arg {
	int pid;

	void *address;

	// Number of values expected to write.
	size_t array;

	// For parsing values.
	cli_val_t value;

	// Values to write.
	const char **values;

	// How many values were passed.
	size_t values_size;

	// Whether to write the same value repeatedly until the program is told
	// to shut down.
	int repeat;
	// A delay in milliseconds before writing to the address again. Without
	// a delay you could theoretically turn your CPU into a heater.
	int repeat_delay;

	// Whether to parse values in binary.
	int binary;

	// Whether to keep the program paused while writing.
	int pause;
};

int cli_cmd_write(struct cli_cmd_write_arg *arg);

#endif /* CLI_CMD_WRITE_H */

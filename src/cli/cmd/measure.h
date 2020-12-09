#ifndef CLI_CMD_MEASURE_H
#define CLI_CMD_MEASURE_H

#include <darr.h>

#include "cli/val/val.h"

struct cli_cmd_measure_arg {
	// At which address the first value would be located.
	void *address;

	// Number of values that would be expected to write.
	size_t array;

	// For parsing values.
	cli_val_t value;

	// Values to write.
	const char **values;
	//
	// How many values were passed.
	size_t values_size;
};

int cli_cmd_measure(struct cli_cmd_measure_arg *arg);

#endif /* CLI_CMD_MEASURE_H */

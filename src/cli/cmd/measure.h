#ifndef CLI_CMD_MEASURE_H
#define CLI_CMD_MEASURE_H

#include "cli/val-list.h"

struct cli_cmd_measure_arg {
	void *address;

	// Number of values that would be expected to write.
	size_t array;

	cli_val_list value_list;
};

int cli_cmd_measure(struct cli_cmd_measure_arg *arg);

#endif /* CLI_CMD_MEASURE_H */

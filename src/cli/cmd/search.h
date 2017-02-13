#ifndef CLI_CMD_SEARCH_H
#define CLI_CMD_SEARCH_H

#include "cli/val.h"
#include "cli/val-list.h"

struct cli_cmd_search_arg {
	int pid;

	// How we're going to interpret values.
	cli_val value;

	// Whether to search readable memory addresses.
	int read;

	// Whether to search writable memory addresses.
	int write;

	// Whether to search executable memory addresses.
	int execute;

	// Whether we're going to read from stdin.
	int input;

	// Whether to perform an equality check.
	int eq;
	cli_val eq_value;

	// Whether to perform a not equals check.
	int ne;
	cli_val ne_value;

	// Whether to perform greather than.
	int gt;
	cli_val gt_value;

	// Whether to perform greather than equals.
	int gte;
	cli_val gte_value;

	// Whether to perform less than.
	int lt;
	cli_val lt_value;

	// Whether to perform less than equals.
	int lte;
	cli_val lte_value;

	// Whether to check if it was incremented.
	int inc;
	cli_val inc_value;

	// Whether to check if it was incremented up to and including value.
	int inc_up_to;
	cli_val inc_up_to_value;

	// Whether to check if it was decremented.
	int dec;
	cli_val dec_value;

	// Whether to check if it was decremented up to and including value.
	int dec_up_to;
	cli_val dec_up_to_value;

	// Whether to check if it was changed.
	int changed;

	// Whether to check if it was unchanged.
	int unchanged;

	// Whether to check if it was increased.
	int increased;

	// Whether to check if it was decreased.
	int decreased;
};

int cli_cmd_search(struct cli_cmd_search_arg *arg);

#endif /* CLI_CMD_SEARCH_H */

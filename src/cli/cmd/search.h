#ifndef CLI_CMD_SEARCH_H
#define CLI_CMD_SEARCH_H

#include "cli/val.h"

struct cli_cmd_search_arg {
	int pid;

	// If not NULL, start searching from this address.
	void *address_start;

	// If not NULL, search up to this address.
	void *address_stop;

	// Regions to search. Set to 0 to search all. Use macros that start
	// with PROCTAL_REGION to choose regions.
	int region;

	// How we're going to interpret values.
	cli_val_t value;

	// Whether to search readable memory addresses.
	int read;

	// Whether to search writable memory addresses.
	int write;

	// Whether to search executable memory addresses.
	int execute;

	// Whether to review the results of a previous search.
	int review;

	// Whether to perform an equality check.
	int eq;
	cli_val_t eq_value;

	// Whether to perform a not equals check.
	int ne;
	cli_val_t ne_value;

	// Whether to perform greather than.
	int gt;
	cli_val_t gt_value;

	// Whether to perform greather than equals.
	int gte;
	cli_val_t gte_value;

	// Whether to perform less than.
	int lt;
	cli_val_t lt_value;

	// Whether to perform less than equals.
	int lte;
	cli_val_t lte_value;

	// Whether to check if it was incremented.
	int inc;
	cli_val_t inc_value;

	// Whether to check if it was incremented up to and including value.
	int inc_up_to;
	cli_val_t inc_up_to_value;

	// Whether to check if it was decremented.
	int dec;
	cli_val_t dec_value;

	// Whether to check if it was decremented up to and including value.
	int dec_up_to;
	cli_val_t dec_up_to_value;

	// Whether to check if it was changed.
	int changed;

	// Whether to check if it was unchanged.
	int unchanged;

	// Whether to check if it was increased.
	int increased;

	// Whether to check if it was decreased.
	int decreased;

	// Whether to keep the program frozen while writing.
	int freeze;
};

int cli_cmd_search(struct cli_cmd_search_arg *arg);

#endif /* CLI_CMD_SEARCH_H */

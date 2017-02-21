#include "cli/val/filter.h"

int cli_val_filter_compare(
	struct cli_val_filter_compare_arg *arg,
	cli_val value);

int cli_val_filter_compare_prev(
	struct cli_val_filter_compare_prev_arg *arg,
	cli_val curr,
	cli_val prev);

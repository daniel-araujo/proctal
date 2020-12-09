#ifndef CLI_VAL_FILTER_H
#define CLI_VAL_FILTER_H

#include "cli/val/val.h"

struct cli_val_filter_compare_arg {
	cli_val_t eq;
	cli_val_t ne;
	cli_val_t gt;
	cli_val_t gte;
	cli_val_t lt;
	cli_val_t lte;
};

struct cli_val_filter_compare_prev_arg {
	int changed;
	int unchanged;
	int increased;
	int decreased;
	cli_val_t inc;
	cli_val_t inc_up_to;
	cli_val_t dec;
	cli_val_t dec_up_to;
};

inline int cli_val_filter_compare(struct cli_val_filter_compare_arg *arg, cli_val_t value)
{
	cli_val_t nil = cli_val_nil();

	if (arg->eq != nil && cli_val_cmp(value, arg->eq) != 0) {
		return 0;
	}

	if (arg->ne != nil && cli_val_cmp(value, arg->ne) == 0) {
		return 0;
	}

	if (arg->gt != nil && cli_val_cmp(value, arg->gt) != 1) {
		return 0;
	}

	if (arg->gte != nil && cli_val_cmp(value, arg->gte) < 0) {
		return 0;
	}

	if (arg->lt != nil && cli_val_cmp(value, arg->lt) != -1) {
		return 0;
	}

	if (arg->lte != nil && cli_val_cmp(value, arg->lte) > 0) {
		return 0;
	}

	return 1;
}

inline int cli_val_filter_compare_prev(struct cli_val_filter_compare_prev_arg *arg, cli_val_t curr, cli_val_t prev)
{
	cli_val_t nil = cli_val_nil();

	if (arg->changed && cli_val_cmp(curr, prev) == 0) {
		return 0;
	}

	if (arg->unchanged && cli_val_cmp(curr, prev) != 0) {
		return 0;
	}

	if (arg->increased && cli_val_cmp(curr, prev) < 1) {
		return 0;
	}

	if (arg->decreased && cli_val_cmp(curr, prev) > -1) {
		return 0;
	}

	if (arg->inc != nil) {
		cli_val_t exactly = cli_val_create_clone(prev);

		if (cli_val_add(exactly, arg->inc)
			&& cli_val_cmp(curr, exactly) != 0) {
			cli_val_destroy(exactly);
			return 0;
		}

		cli_val_destroy(exactly);
	}

	if (arg->inc_up_to != nil) {
		cli_val_t up_to = cli_val_create_clone(prev);

		if (cli_val_add(up_to, arg->inc_up_to)
			&& !(cli_val_cmp(curr, up_to) <= 0 && cli_val_cmp(curr, prev) > 0)) {
			cli_val_destroy(up_to);
			return 0;
		}

		cli_val_destroy(up_to);
	}

	if (arg->dec != nil) {
		cli_val_t exactly = cli_val_create_clone(prev);

		if (cli_val_sub(exactly, arg->dec)
			&& cli_val_cmp(curr, exactly) != 0) {
			cli_val_destroy(exactly);
			return 0;
		}

		cli_val_destroy(exactly);
	}

	if (arg->dec_up_to != nil) {
		cli_val_t up_to = cli_val_create_clone(prev);

		if (cli_val_sub(up_to, arg->dec_up_to)
			&& !(cli_val_cmp(curr, up_to) >= 0 && cli_val_cmp(curr, prev) < 0)) {
			cli_val_destroy(up_to);
			return 0;
		}

		cli_val_destroy(up_to);
	}

	return 1;
}

#endif /* CLI_VAL_FILTER_H */

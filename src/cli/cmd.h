#ifndef CMD_H
#define CMD_H

#include "cmd/val.h"

struct proctal_cmd_read_arg {
	int pid;

	void *address;

	enum proctal_cmd_val_type type;
};

struct proctal_cmd_write_arg {
	int pid;

	void *address;

	enum proctal_cmd_val_type type;

	void* value;
};

struct proctal_cmd_search_arg {
	int pid;

	enum proctal_cmd_val_type type;

	// Whether we're going to read from stdin.
	int input;

	// Whether to perform an equality check.
	int eq;
	void* eq_value;

	// Whether to perform a not equals check.
	int ne;
	void* ne_value;

	// Whether to perform greather than.
	int gt;
	void* gt_value;

	// Whether to perform greather than equals.
	int gte;
	void* gte_value;

	// Whether to perform less than.
	int lt;
	void* lt_value;

	// Whether to perform less than equals.
	int lte;
	void* lte_value;

	// Whether to check if it was incremented.
	int inc;
	void* inc_value;

	// Whether to check if it was incremented up to and including value.
	int inc_up_to;
	void* inc_up_to_value;

	// Whether to check if it was decremented.
	int dec;
	void* dec_value;

	// Whether to check if it was decremented up to and including value.
	int dec_up_to;
	void* dec_up_to_value;

	// Whether to check if it was changed.
	int changed;

	// Whether to check if it was unchanged.
	int unchanged;

	// Whether to check if it was increased.
	int increased;

	// Whether to check if it was decreased.
	int decreased;
};

int proctal_cmd_read(struct proctal_cmd_read_arg *arg);

int proctal_cmd_write(struct proctal_cmd_write_arg *arg);

int proctal_cmd_search(struct proctal_cmd_search_arg *arg);

#endif /* CMD_H */

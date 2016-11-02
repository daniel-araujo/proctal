#include <proctal.h>

#include "cmd.h"

static inline int pass_search_filters(struct proctal_cmd_search_arg *arg, void *value)
{
	if (arg->eq && proctal_cmd_val_cmp(arg->type, value, arg->eq_value) != 0) {
		return 0;
	}

	if (arg->gt && proctal_cmd_val_cmp(arg->type, value, arg->gt_value) != 1) {
		return 0;
	}

	if (arg->gte && proctal_cmd_val_cmp(arg->type, value, arg->gte_value) < 0) {
		return 0;
	}

	if (arg->lt && proctal_cmd_val_cmp(arg->type, value, arg->lt_value) != -1) {
		return 0;
	}

	if (arg->lte && proctal_cmd_val_cmp(arg->type, value, arg->lte_value) > 0) {
		return 0;
	}

	if (arg->ne && proctal_cmd_val_cmp(arg->type, value, arg->ne_value) == 0) {
		return 0;
	}

	return 1;
}

static inline int pass_search_filters_p(struct proctal_cmd_search_arg *arg, void *value, void *previous_value)
{
	if (arg->changed && proctal_cmd_val_cmp(arg->type, value, previous_value) == 0) {
		return 0;
	}

	if (arg->unchanged && proctal_cmd_val_cmp(arg->type, value, previous_value) != 0) {
		return 0;
	}

	if (arg->increased && proctal_cmd_val_cmp(arg->type, value, previous_value) < 1) {
		return 0;
	}

	if (arg->decreased && proctal_cmd_val_cmp(arg->type, value, previous_value) > -1) {
		return 0;
	}

	if (arg->inc) {
		char exactly[proctal_cmd_val_size(arg->type)];

		if (proctal_cmd_val_add(arg->type, previous_value, arg->inc_value, &exactly)
			&& proctal_cmd_val_cmp(arg->type, value, exactly) != 0) {
			return 0;
		}
	}

	if (arg->inc_up_to) {
		char upto[proctal_cmd_val_size(arg->type)];

		if (proctal_cmd_val_add(arg->type, previous_value, arg->inc_up_to_value, &upto)
			&& !(proctal_cmd_val_cmp(arg->type, value, upto) <= 0
				&& proctal_cmd_val_cmp(arg->type, value, previous_value) > 0)) {
			return 0;
		}
	}

	if (arg->dec) {
		char exactly[proctal_cmd_val_size(arg->type)];

		if (proctal_cmd_val_sub(arg->type, previous_value, arg->dec_value, &exactly)
			&& proctal_cmd_val_cmp(arg->type, value, exactly) != 0) {
			return 0;
		}
	}

	if (arg->dec_up_to) {
		char upto[proctal_cmd_val_size(arg->type)];

		if (proctal_cmd_val_sub(arg->type, previous_value, arg->dec_up_to_value, &upto)
			&& !(proctal_cmd_val_cmp(arg->type, value, upto) >= 0
				&& proctal_cmd_val_cmp(arg->type, value, previous_value) < 0)) {
			return 0;
		}
	}

	return 1;
}

static inline void print_search_match(void *addr, enum proctal_cmd_val_type type, void *value)
{
	proctal_cmd_val_print(stdout, PROCTAL_CMD_VAL_TYPE_ADDRESS, &addr);
	printf(" ");
	proctal_cmd_val_print(stdout, type, value);
	printf("\n");
}

static inline void search_process(struct proctal_cmd_search_arg *arg, proctal p)
{
	size_t size = proctal_cmd_val_size(arg->type);

	proctal_addr_iter iter = proctal_addr_iter_create(p);
	proctal_addr_iter_set_align(iter, proctal_cmd_val_align(arg->type));
	proctal_addr_iter_set_size(iter, size);

	void *addr;
	char value[size];

	while (proctal_addr_iter_next(iter, &addr) == 0) {
		if (proctal_read(p, addr, value, size) != 0) {
			continue;
		}

		if (!pass_search_filters(arg, value)) {
			continue;
		}

		print_search_match(addr, arg->type, value);
	}

	proctal_addr_iter_destroy(iter);
}

static inline void search_input(struct proctal_cmd_search_arg *arg, proctal p)
{
	size_t size = proctal_cmd_val_size(arg->type);
	void *addr;
	char value[size];
	char previous_value[size];

	for (;;) {
		if (scanf("%lx", (unsigned long *) &addr) != 1) {
			break;
		}

		if (!proctal_cmd_val_scan(stdin, arg->type, previous_value)) {
			break;
		}

		if (proctal_read(p, addr, value, size) != 0) {
			// Can't seem to read anymore. Dropping it.
			continue;
		}

		if (!pass_search_filters(arg, value)) {
			continue;
		}

		if (!pass_search_filters_p(arg, value, previous_value)) {
			continue;
		}

		print_search_match(addr, arg->type, value);
	}
}

int proctal_cmd_search(struct proctal_cmd_search_arg *arg)
{
	proctal p = proctal_create();

	if (p == NULL) {
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	if (arg->input) {
		search_input(arg, p);
	} else {
		search_process(arg, p);
	}

	proctal_destroy(p);

	return 0;
}

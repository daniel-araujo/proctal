#include <proctal.h>

#include "cmd.h"

static inline int pass_search_filters(struct proctal_cmd_search_arg *arg, void *value)
{
	if (arg->eq && proctal_cmd_val_cmp(value, arg->eq_value) != 0) {
		return 0;
	}

	if (arg->gt && proctal_cmd_val_cmp(value, arg->gt_value) != 1) {
		return 0;
	}

	if (arg->gte && proctal_cmd_val_cmp(value, arg->gte_value) < 0) {
		return 0;
	}

	if (arg->lt && proctal_cmd_val_cmp(value, arg->lt_value) != -1) {
		return 0;
	}

	if (arg->lte && proctal_cmd_val_cmp(value, arg->lte_value) > 0) {
		return 0;
	}

	if (arg->ne && proctal_cmd_val_cmp(value, arg->ne_value) == 0) {
		return 0;
	}

	return 1;
}

static inline int pass_search_filters_p(struct proctal_cmd_search_arg *arg, proctal_cmd_val value, proctal_cmd_val previous_value)
{
	if (arg->changed && proctal_cmd_val_cmp(value, previous_value) == 0) {
		return 0;
	}

	if (arg->unchanged && proctal_cmd_val_cmp(value, previous_value) != 0) {
		return 0;
	}

	if (arg->increased && proctal_cmd_val_cmp(value, previous_value) < 1) {
		return 0;
	}

	if (arg->decreased && proctal_cmd_val_cmp(value, previous_value) > -1) {
		return 0;
	}

	if (arg->inc) {
		proctal_cmd_val exactly = proctal_cmd_val_create(arg->value_attr);

		if (proctal_cmd_val_add(previous_value, arg->inc_value, exactly)
			&& proctal_cmd_val_cmp(value, exactly) != 0) {
			proctal_cmd_val_destroy(exactly);
			return 0;
		}

		proctal_cmd_val_destroy(exactly);
	}

	if (arg->inc_up_to) {
		proctal_cmd_val upto = proctal_cmd_val_create(arg->value_attr);

		if (proctal_cmd_val_add(previous_value, arg->inc_up_to_value, upto)
			&& !(proctal_cmd_val_cmp(value, upto) <= 0
				&& proctal_cmd_val_cmp(value, previous_value) > 0)) {
			proctal_cmd_val_destroy(upto);
			return 0;
		}

		proctal_cmd_val_destroy(upto);
	}

	if (arg->dec) {
		proctal_cmd_val exactly = proctal_cmd_val_create(arg->value_attr);

		if (proctal_cmd_val_sub(previous_value, arg->dec_value, exactly)
			&& proctal_cmd_val_cmp(value, exactly) != 0) {
			proctal_cmd_val_destroy(exactly);
			return 0;
		}

		proctal_cmd_val_destroy(exactly);
	}

	if (arg->dec_up_to) {
		proctal_cmd_val upto = proctal_cmd_val_create(arg->value_attr);

		if (proctal_cmd_val_sub(previous_value, arg->dec_up_to_value, upto)
			&& !(proctal_cmd_val_cmp(value, upto) >= 0
				&& proctal_cmd_val_cmp(value, previous_value) < 0)) {
			proctal_cmd_val_destroy(upto);
			return 0;
		}

		proctal_cmd_val_destroy(upto);
	}

	return 1;
}

static inline void print_search_match(proctal_cmd_val addr, proctal_cmd_val value)
{
	proctal_cmd_val_print(addr, stdout);
	printf(" ");
	proctal_cmd_val_print(value, stdout);
	printf("\n");
}

static inline void search_process(struct proctal_cmd_search_arg *arg, proctal p)
{
	proctal_cmd_val_attr addr_attr = proctal_cmd_val_attr_create(PROCTAL_CMD_VAL_TYPE_ADDRESS);
	proctal_cmd_val addr = proctal_cmd_val_create(addr_attr);
	proctal_cmd_val_attr_destroy(addr_attr);

	proctal_cmd_val value = proctal_cmd_val_create(arg->value_attr);

	size_t size = proctal_cmd_val_sizeof(value);

	proctal_addr_iter iter = proctal_addr_iter_create(p);

	switch (proctal_error(p)) {
	case 0:
		break;

	case PROCTAL_ERROR_OUT_OF_MEMORY:
		fprintf(stderr, "Out of memory.\n");
		return;

	default:
		fprintf(stderr, "Failed to create a Proctal address iterator.\n");
		return;
	}

	proctal_addr_iter_set_align(iter, proctal_cmd_val_alignof(value));
	proctal_addr_iter_set_size(iter, size);
	proctal_addr_iter_set_region(iter, 0);

	while (proctal_addr_iter_next(iter, (void **) proctal_cmd_val_addr(addr))) {
		if (proctal_read(p, *(void **) proctal_cmd_val_addr(addr), proctal_cmd_val_addr(value), size) != size) {
			switch (proctal_error(p)) {
			case PROCTAL_ERROR_PERMISSION_DENIED:
				fprintf(stderr, "No permission to read from address ");
				proctal_cmd_val_print(addr, stderr);
				fprintf(stderr, "\n");
				proctal_error_ack(p);
				break;

			default:
				fprintf(stderr, "Failed to read from address ");
				proctal_cmd_val_print(addr, stderr);
				fprintf(stderr, "\n");
				proctal_error_ack(p);
				break;
			}

			continue;
		}

		if (!pass_search_filters(arg, value)) {
			continue;
		}

		print_search_match(addr, value);
	}

	switch (proctal_error(p)) {
	case 0:
		break;

	case PROCTAL_ERROR_PERMISSION_DENIED:
		fprintf(stderr, "No permission.\n");
		proctal_error_ack(p);
		break;

	default:
		fprintf(stderr, "Failed to search all addresses.\n");
		proctal_error_ack(p);
		break;
	}

	proctal_addr_iter_destroy(iter);
}

static inline void search_input(struct proctal_cmd_search_arg *arg, proctal p)
{
	proctal_cmd_val_attr addr_attr = proctal_cmd_val_attr_create(PROCTAL_CMD_VAL_TYPE_ADDRESS);
	proctal_cmd_val addr = proctal_cmd_val_create(addr_attr);
	proctal_cmd_val_attr_destroy(addr_attr);

	proctal_cmd_val value = proctal_cmd_val_create(arg->value_attr);
	proctal_cmd_val previous_value = proctal_cmd_val_create(arg->value_attr);

	for (;;) {
		if (!proctal_cmd_val_scan(addr, stdin)) {
			break;
		}

		if (!proctal_cmd_val_scan(previous_value, stdin)) {
			break;
		}

		size_t size = proctal_cmd_val_sizeof(previous_value);

		if (proctal_read(p, *(void **) proctal_cmd_val_addr(addr), proctal_cmd_val_addr(value), size) != size) {
			switch (proctal_error(p)) {
			case PROCTAL_ERROR_PERMISSION_DENIED:
				fprintf(stderr, "No permission to read from address ");
				proctal_cmd_val_print(addr, stderr);
				fprintf(stderr, "\n");
				proctal_error_ack(p);
				break;

			default:
				fprintf(stderr, "Failed to read from address ");
				proctal_cmd_val_print(addr, stderr);
				fprintf(stderr, "\n");
				proctal_error_ack(p);
				break;
			}

			// Can't seem to read anymore. Dropping it.
			continue;
		}

		if (!pass_search_filters(arg, value)) {
			continue;
		}

		if (!pass_search_filters_p(arg, value, previous_value)) {
			continue;
		}

		print_search_match(addr, value);
	}
}

int proctal_cmd_search(struct proctal_cmd_search_arg *arg)
{
	proctal p = proctal_create();

	switch (proctal_error(p)) {
	case 0:
		break;

	case PROCTAL_ERROR_OUT_OF_MEMORY:
		fprintf(stderr, "Out of memory.\n");
		proctal_destroy(p);
		return 1;

	default:
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		proctal_destroy(p);
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

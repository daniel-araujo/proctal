#include <proctal.h>

#include "cmd.h"
#include "printer.h"
#include "scanner.h"

static inline int pass_search_filters(struct cli_cmd_search_arg *arg, void *value)
{
	if (arg->eq && cli_val_cmp(value, arg->eq_value) != 0) {
		return 0;
	}

	if (arg->gt && cli_val_cmp(value, arg->gt_value) != 1) {
		return 0;
	}

	if (arg->gte && cli_val_cmp(value, arg->gte_value) < 0) {
		return 0;
	}

	if (arg->lt && cli_val_cmp(value, arg->lt_value) != -1) {
		return 0;
	}

	if (arg->lte && cli_val_cmp(value, arg->lte_value) > 0) {
		return 0;
	}

	if (arg->ne && cli_val_cmp(value, arg->ne_value) == 0) {
		return 0;
	}

	return 1;
}

static inline int pass_search_filters_p(struct cli_cmd_search_arg *arg, cli_val value, cli_val previous_value)
{
	if (arg->changed && cli_val_cmp(value, previous_value) == 0) {
		return 0;
	}

	if (arg->unchanged && cli_val_cmp(value, previous_value) != 0) {
		return 0;
	}

	if (arg->increased && cli_val_cmp(value, previous_value) < 1) {
		return 0;
	}

	if (arg->decreased && cli_val_cmp(value, previous_value) > -1) {
		return 0;
	}

	if (arg->inc) {
		cli_val exactly = cli_val_create(arg->value_attr);

		if (cli_val_add(previous_value, arg->inc_value, exactly)
			&& cli_val_cmp(value, exactly) != 0) {
			cli_val_destroy(exactly);
			return 0;
		}

		cli_val_destroy(exactly);
	}

	if (arg->inc_up_to) {
		cli_val upto = cli_val_create(arg->value_attr);

		if (cli_val_add(previous_value, arg->inc_up_to_value, upto)
			&& !(cli_val_cmp(value, upto) <= 0
				&& cli_val_cmp(value, previous_value) > 0)) {
			cli_val_destroy(upto);
			return 0;
		}

		cli_val_destroy(upto);
	}

	if (arg->dec) {
		cli_val exactly = cli_val_create(arg->value_attr);

		if (cli_val_sub(previous_value, arg->dec_value, exactly)
			&& cli_val_cmp(value, exactly) != 0) {
			cli_val_destroy(exactly);
			return 0;
		}

		cli_val_destroy(exactly);
	}

	if (arg->dec_up_to) {
		cli_val upto = cli_val_create(arg->value_attr);

		if (cli_val_sub(previous_value, arg->dec_up_to_value, upto)
			&& !(cli_val_cmp(value, upto) >= 0
				&& cli_val_cmp(value, previous_value) < 0)) {
			cli_val_destroy(upto);
			return 0;
		}

		cli_val_destroy(upto);
	}

	return 1;
}

static inline void print_search_match(cli_val addr, cli_val value)
{
	cli_val_print(addr, stdout);
	printf(" ");
	cli_val_print(value, stdout);
	printf("\n");
}

static inline void search_process(struct cli_cmd_search_arg *arg, proctal p)
{
	cli_val_attr addr_attr = cli_val_attr_create(CLI_VAL_TYPE_ADDRESS);
	cli_val addr = cli_val_create(addr_attr);
	cli_val_attr_destroy(addr_attr);

	cli_val value = cli_val_create(arg->value_attr);

	size_t size = cli_val_sizeof(value);

	proctal_addr_iter iter = proctal_addr_iter_create(p);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return;
	}

	proctal_addr_iter_set_align(iter, cli_val_alignof(value));
	proctal_addr_iter_set_size(iter, size);
	proctal_addr_iter_set_region(iter, 0);

	while (proctal_addr_iter_next(iter, (void **) cli_val_addr(addr))) {
		if (proctal_read(p, *(void **) cli_val_addr(addr), cli_val_addr(value), size) != size) {
			switch (proctal_error(p)) {
			case PROCTAL_ERROR_PERMISSION_DENIED:
				fprintf(stderr, "No permission to read from address ");
				cli_val_print(addr, stderr);
				fprintf(stderr, "\n");
				proctal_error_ack(p);
				break;

			default:
				fprintf(stderr, "Failed to read from address ");
				cli_val_print(addr, stderr);
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

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_error_ack(p);
		return;
	}

	proctal_addr_iter_destroy(iter);
	cli_val_destroy(value);
	cli_val_destroy(addr);
}

static inline void search_input(struct cli_cmd_search_arg *arg, proctal p)
{
	cli_val_attr addr_attr = cli_val_attr_create(CLI_VAL_TYPE_ADDRESS);
	cli_val addr = cli_val_create(addr_attr);
	cli_val_attr_destroy(addr_attr);

	cli_val value = cli_val_create(arg->value_attr);
	cli_val previous_value = cli_val_create(arg->value_attr);

	for (;;) {
		cli_scan_skip_chars(stdin, "\n ");

		if (feof(stdin)) {
			// It's over.
			break;
		}

		if (!cli_val_scan(addr, stdin)) {
			fprintf(stderr, "Failed to read address.\n");

			cli_scan_skip_until_chars(stdin, "\n");
			continue;
		}

		cli_scan_skip_chars(stdin, " ");

		if (!cli_val_scan(previous_value, stdin)) {
			fprintf(stderr, "Failed to parse previous value of address ");
			cli_val_print(addr, stderr);
			fprintf(stderr, ".\n");

			cli_scan_skip_until_chars(stdin, "\n");
			continue;
		}

		size_t size = cli_val_sizeof(previous_value);

		if (proctal_read(p, *(void **) cli_val_addr(addr), cli_val_addr(value), size) != size) {
			switch (proctal_error(p)) {
			case PROCTAL_ERROR_PERMISSION_DENIED:
				fprintf(stderr, "No permission to read from address ");
				cli_val_print(addr, stderr);
				fprintf(stderr, ".\n");
				proctal_error_ack(p);
				break;

			default:
				fprintf(stderr, "Failed to read from address ");
				cli_val_print(addr, stderr);
				fprintf(stderr, ".\n");
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

int cli_cmd_search(struct cli_cmd_search_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
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

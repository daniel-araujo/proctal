#include <string.h>
#include <proctal.h>

#include "cmd.h"
#include "printer.h"
#include "scanner.h"

struct buffer {
	char *data;
	size_t size;
};

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
		cli_val exactly = cli_val_create_clone(arg->value);

		if (cli_val_add(previous_value, arg->inc_value, exactly)
			&& cli_val_cmp(value, exactly) != 0) {
			cli_val_destroy(exactly);
			return 0;
		}

		cli_val_destroy(exactly);
	}

	if (arg->inc_up_to) {
		cli_val upto = cli_val_create_clone(arg->value);

		if (cli_val_add(previous_value, arg->inc_up_to_value, upto)
			&& !(cli_val_cmp(value, upto) <= 0
				&& cli_val_cmp(value, previous_value) > 0)) {
			cli_val_destroy(upto);
			return 0;
		}

		cli_val_destroy(upto);
	}

	if (arg->dec) {
		cli_val exactly = cli_val_create_clone(arg->value);

		if (cli_val_sub(previous_value, arg->dec_value, exactly)
			&& cli_val_cmp(value, exactly) != 0) {
			cli_val_destroy(exactly);
			return 0;
		}

		cli_val_destroy(exactly);
	}

	if (arg->dec_up_to) {
		cli_val upto = cli_val_create_clone(arg->value);

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

static inline void *align_addr(void *addr, size_t align)
{
	ptrdiff_t offset = ((unsigned long) addr % align);

	if (offset != 0) {
		offset = align - offset;
	}

	return (void *) ((char *) addr + offset);
}

static inline void search_process(struct cli_cmd_search_arg *arg, proctal p)
{
	cli_val addr = cli_val_wrap(CLI_VAL_TYPE_ADDRESS, cli_val_address_create());
	cli_val value = arg->value;

	size_t size = cli_val_sizeof(value);
	size_t align = cli_val_alignof(value);

	proctal_region_set_mask(p, 0);

	proctal_region_new(p);

	const size_t buffer_size = 1024 * 1024;

	struct buffer curr_buffer = {
		.data = malloc(buffer_size),
		.size = 0
	};
	struct buffer prev_buffer = {
		.data = malloc(buffer_size),
		.size = 0
	};

	void *start, *end;

	while (proctal_region(p, &start, &end)) {
		size_t leftover = 0;

		for (size_t chunk = 0;;++chunk) {
			// This is the starting address of the current chunk.
			char *offset = (char *) start + buffer_size * chunk;

			offset = (char *) align_addr(offset, align);

			if (offset >= (char *) end) {
				break;
			}

			size_t chunk_size = (char *) end - offset;

			if (chunk_size > buffer_size) {
				chunk_size = buffer_size;
			}

			proctal_read(p, offset, curr_buffer.data, chunk_size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);
				proctal_error_ack(p);
				break;
			}

			curr_buffer.size = chunk_size;

			if (leftover) {
				// The word rightover isn't even an English
				// word but serves as a very literal
				// counterpart to the leftover variable.
				size_t rightover = size - leftover;

				// Read what's left from the previous chunk.
				memcpy(cli_val_raw(value), prev_buffer.data + prev_buffer.size - leftover, leftover);
				memcpy((char *) cli_val_raw(value) + leftover, curr_buffer.data + rightover, rightover);

				if (pass_search_filters(arg, value)) {
					void *a = offset - leftover;
					cli_val_parse_bin(addr, (char *) &a, sizeof a);

					print_search_match(addr, value);
				}

				leftover = 0;
			}

			size_t i = 0; 

			while (i < curr_buffer.size) {
				if ((i + size) > curr_buffer.size) {
					leftover = curr_buffer.size - i;
				}

				memcpy(cli_val_raw(value), curr_buffer.data + i, size);

				if (pass_search_filters(arg, value)) {
					void *a = offset + i;
					cli_val_parse_bin(addr, (char *) &a, sizeof a);

					print_search_match(addr, value);
				}

				i += align;
			}

			leftover = curr_buffer.size - i;

			memcpy(prev_buffer.data, curr_buffer.data, curr_buffer.size);
			prev_buffer.size = curr_buffer.size;
		}
	}

	cli_val_destroy(addr);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_error_ack(p);
		return;
	}
}

static inline void search_input(struct cli_cmd_search_arg *arg, proctal p)
{
	cli_val addr = cli_val_wrap(CLI_VAL_TYPE_ADDRESS, cli_val_address_create());
	cli_val value = arg->value;
	cli_val previous_value = cli_val_create_clone(value);

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

		if (proctal_read(p, *(void **) cli_val_raw(addr), cli_val_raw(value), size) != size) {
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

	cli_val_destroy(addr);
	cli_val_destroy(previous_value);
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

	if (!arg->read && !arg->write && !arg->execute) {
		// By default will search readable memory.
		proctal_address_set_read(p, 1);
		proctal_address_set_write(p, 0);
		proctal_address_set_execute(p, 0);

		proctal_region_set_read(p, 1);
		proctal_region_set_write(p, 0);
		proctal_region_set_execute(p, 0);
	} else {
		proctal_address_set_read(p, arg->read);
		proctal_address_set_write(p, arg->write);
		proctal_address_set_execute(p, arg->execute);

		proctal_region_set_read(p, arg->read);
		proctal_region_set_write(p, arg->write);
		proctal_region_set_execute(p, arg->execute);
	}

	if (arg->input) {
		search_input(arg, p);
	} else {
		search_process(arg, p);
	}

	proctal_destroy(p);

	return 0;
}

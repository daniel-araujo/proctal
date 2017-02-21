#include <string.h>

#include "cli/cmd/search.h"
#include "cli/printer.h"
#include "cli/scanner.h"
#include "cli/val.h"
#include "cli/val/filter.h"
#include "lib/include/proctal.h"
#include "swbuf/swbuf.h"
#include "chunk/chunk.h"

static inline struct cli_val_filter_compare_arg *create_filter_compare_arg(struct cli_cmd_search_arg *arg)
{
	struct cli_val_filter_compare_arg *filter_arg = malloc(sizeof(*filter_arg));

	cli_val nil = cli_val_nil();

#define COPY(NAME) \
	if (arg->NAME) { \
		filter_arg->NAME = arg->NAME##_value; \
	} else { \
		filter_arg->NAME = nil; \
	}

	COPY(eq);
	COPY(ne);
	COPY(gt);
	COPY(gte);
	COPY(lt);
	COPY(lte);

#undef COPY

	return filter_arg;
}

static inline void destroy_filter_compare_arg(struct cli_val_filter_compare_arg *filter_arg)
{
	free(filter_arg);
}

static inline struct cli_val_filter_compare_prev_arg *create_filter_compare_prev_arg(struct cli_cmd_search_arg *arg)
{
	struct cli_val_filter_compare_prev_arg *filter_arg = malloc(sizeof(*filter_arg));

	filter_arg->changed = arg->changed;
	filter_arg->unchanged = arg->unchanged;
	filter_arg->increased = arg->increased;
	filter_arg->decreased = arg->decreased;

	cli_val nil = cli_val_nil();

#define COPY(NAME) \
	if (arg->NAME) { \
		filter_arg->NAME = arg->NAME##_value; \
	} else { \
		filter_arg->NAME = nil; \
	}

	COPY(inc);
	COPY(inc_up_to);
	COPY(dec);
	COPY(dec_up_to);

#undef COPY

	return filter_arg;
}

static inline void destroy_filter_compare_prev_arg(struct cli_val_filter_compare_prev_arg *filter_arg)
{
	free(filter_arg);
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
	struct cli_val_filter_compare_arg *filter_compare_arg = create_filter_compare_arg(arg);

	cli_val addr = cli_val_wrap(CLI_VAL_TYPE_ADDRESS, cli_val_address_create());
	cli_val value = arg->value;

	size_t size = cli_val_sizeof(value);
	size_t align = cli_val_alignof(value);

	proctal_region_set_mask(p, 0);

	proctal_region_new(p);

	const size_t buffer_size = 1024 * 1024;
	struct swbuf buf;
	swbuf_init(&buf, buffer_size);

	size_t prev_size, curr_size;
	void *start, *end;

	struct chunk chunk;

	while (proctal_region(p, &start, &end)) {
		size_t leftover = 0;

		chunk_init(&chunk, start, end, buffer_size);

		do {
			char *offset = align_addr(chunk_offset(&chunk), align);
			curr_size = chunk_size(&chunk);

			proctal_read(p, offset, swbuf_address_offset(&buf, 0), curr_size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);
				proctal_error_ack(p);
				break;
			}

			if (leftover) {
				// The word rightover isn't even an English
				// word but serves as a very literal
				// counterpart to the leftover variable.
				size_t rightover = size - leftover;

				// Read what's left from the previous chunk.
				memcpy(cli_val_raw(value), swbuf_address_offset(&buf, prev_size - leftover - buffer_size), leftover);
				memcpy((char *) cli_val_raw(value) + leftover, swbuf_address_offset(&buf, rightover), rightover);

				if (cli_val_filter_compare(filter_compare_arg, value)) {
					void *a = offset - leftover;
					cli_val_parse_bin(addr, (char *) &a, sizeof(a));

					print_search_match(addr, value);
				}

				leftover = 0;
			}

			size_t i = 0;

			while (i < curr_size) {
				if ((i + size) > curr_size) {
					leftover = curr_size - i;
				}

				memcpy(cli_val_raw(value), swbuf_address_offset(&buf, i), size);

				if (cli_val_filter_compare(filter_compare_arg, value)) {
					void *a = offset + i;
					cli_val_parse_bin(addr, (char *) &a, sizeof(a));

					print_search_match(addr, value);
				}

				i += align;
			}

			leftover = curr_size - i;

			swbuf_swap(&buf);

			// Remembering the size of the previous chunk.
			prev_size = curr_size;
		} while (chunk_next(&chunk));
	}

	swbuf_deinit(&buf);

	cli_val_destroy(addr);

	destroy_filter_compare_arg(filter_compare_arg);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_error_ack(p);
		return;
	}
}

static inline void search_input(struct cli_cmd_search_arg *arg, proctal p)
{
	struct cli_val_filter_compare_arg *filter_compare_arg = create_filter_compare_arg(arg);
	struct cli_val_filter_compare_prev_arg *filter_compare_prev_arg = create_filter_compare_prev_arg(arg);

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

		if (proctal_read(p, DEREF(void *, cli_val_raw(addr)), cli_val_raw(value), size) != size) {
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

		if (!cli_val_filter_compare(filter_compare_arg, value)) {
			continue;
		}

		if (!cli_val_filter_compare_prev(filter_compare_prev_arg, value, previous_value)) {
			continue;
		}

		print_search_match(addr, value);
	}

	cli_val_destroy(addr);
	cli_val_destroy(previous_value);

	destroy_filter_compare_prev_arg(filter_compare_prev_arg);
	destroy_filter_compare_arg(filter_compare_arg);
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

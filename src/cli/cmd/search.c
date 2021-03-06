#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "cli/cmd/search.h"
#include "cli/printer.h"
#include "cli/scanner.h"
#include "cli/val/val.h"
#include "cli/val/filter.h"
#include "api/include/proctal.h"
#include "swbuf/swbuf.h"
#include "chunk/chunk.h"
#include "riter/riter.h"

static inline struct cli_val_filter_compare_arg *create_filter_compare_arg(struct cli_cmd_search_arg *arg)
{
	struct cli_val_filter_compare_arg *filter_arg = malloc(sizeof(*filter_arg));

	cli_val_t nil = cli_val_nil();

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

	cli_val_t nil = cli_val_nil();

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

static inline void print_search_match(cli_val_t address, cli_val_t value)
{
	cli_val_print(address, stdout);
	printf(" ");
	cli_val_print(value, stdout);
	printf("\n");
}

static inline void *align_address(void *address, size_t align)
{
	ptrdiff_t offset = ((uintptr_t) address % align);

	if (offset != 0) {
		offset = align - offset;
	}

	return (void *) ((char *) address + offset);
}

struct search_user {
	proctal_t p;
};

static int search_reader(void *user, void *src, void *out, size_t size)
{
	struct search_user *real_user = (struct search_user *) user;

	return proctal_read(real_user->p, src, out, size) == size;
}

/*
 * Matches against the contents in memory.
 *
 * Returns 0 on failure, 1 on success.
 */
static inline int search_program(struct cli_cmd_search_arg *arg, proctal_t p)
{
	int ret = 0;

	struct cli_val_filter_compare_arg *filter_compare_arg = create_filter_compare_arg(arg);

	// The value that is matched.
	cli_val_t value = arg->value;

	// We use a cli_val_t to represent the address of the match.
	cli_val_t address = cli_val_wrap(CLI_VAL_TYPE_ADDRESS, cli_val_address_create());

	proctal_scan_region_start(p);

	void *address_start = arg->address_start;
	void *address_stop = arg->address_stop;

	if (address_start == NULL) {
		// Assuming NULL is 0.
	}

	if (address_stop == NULL) {
		// Search until the end.
		address_stop = (char *) ~((uintptr_t) 0);
	}

	// Region start and end addresses.
	void *start, *end;

	while (proctal_scan_region_next(p, &start, &end)) {
		if (start < address_start) {
			start = address_start;
		}

		if (end > address_stop) {
			end = address_stop;
		}

		if (start >= end) {
			// Out of range.
			continue;
		}

		struct riter riter;

		riter_init(&riter, &(struct riter_config) {
			.reader = search_reader,
			.source = start,
			.source_size = (char *) end - (char *) start,
			.buffer_size = 1024 * 1024,
			.data_size = cli_val_sizeof(value),
			.data_align = cli_val_alignof(value),
			.user = &(struct search_user) { p }
		});

		if (riter_error(&riter)) {
			cli_print_riter_error(&riter);
			continue;
		}

		while (!riter_end(&riter)) {
			if (riter_error(&riter)) {
				cli_print_riter_error(&riter);

				// Riter makes calls to proctal sometimes.
				if (proctal_error(p)) {
					cli_print_proctal_error(p);

					if (!proctal_error_recover(p)) {
						// Complete failure. Gotta leave.
						riter_deinit(&riter);
						goto exit_destroy_address;
					}
				}

				// Give up on this region.
				break;
			}

			cli_val_parse_binary(
				value,
				riter_data(&riter),
				riter_data_size(&riter));

			if (cli_val_filter_compare(filter_compare_arg, value)) {
				// Need to store in a temporary variable so that
				// we have an address. That's right, an address
				// to an address.
				void *a = riter_offset(&riter);
				cli_val_parse_binary(address, &a, sizeof(a));

				print_search_match(address, value);
			}

			riter_next(&riter);
		}

		riter_deinit(&riter);
	}

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit_destroy_address;
	}

	ret = 1;
exit_destroy_address:
	cli_val_destroy(address);
	destroy_filter_compare_arg(filter_compare_arg);
	proctal_scan_region_stop(p);
	return ret;
}

#define PARSE_INPUT_ERROR_INVALID_ADDRESS 2
#define PARSE_INPUT_ERROR_INVALID_VALUE 3

/*
 * Parses input in the same format that this command would have printed.
 *
 * The standard input stream will be consumed up to the first new line
 * character.
 *
 * Returns 0 on success, an error code on failure.
 *
 * If the error code is PARSE_INPUT_ERROR_INVALID_VALUE, the address can be
 * assumed to have been parsed correctly.
 */
static inline int parse_input(cli_val_t address, cli_val_t value)
{
	if (!cli_val_scan(address, stdin)) {
		cli_scan_skip_until_chars(stdin, "\n");
		return PARSE_INPUT_ERROR_INVALID_ADDRESS;
	}

	cli_scan_skip_chars(stdin, " ");

	if (!cli_val_scan(value, stdin)) {
		cli_scan_skip_until_chars(stdin, "\n");
		return PARSE_INPUT_ERROR_INVALID_VALUE;
	}

	return 0;
}

/*
 * Handles an input error.
 *
 * Returns 1 if it handled, 0 if it did nothing.
 */
static inline int handle_parse_input_error(int code, cli_val_t address)
{
	switch (code) {
	case 0:
		return 0;

	case PARSE_INPUT_ERROR_INVALID_ADDRESS:
		fprintf(stderr, "Failed to read address.\n");
		return 1;

	case PARSE_INPUT_ERROR_INVALID_VALUE:
		fprintf(stderr, "Failed to parse previous value of address ");
		cli_val_print(address, stderr);
		fprintf(stderr, ".\n");
		return 1;

	default:
		fprintf(stderr, "Failed to read line.\n");
		return 1;
	}
}

/*
 * Handles a read failure in Proctal when attempting to read from an address
 * from a previous search.
 *
 * Returns 1 on success, 0 on failure.
 */
static inline int handle_proctal_read_previous_error(proctal_t p, cli_val_t address)
{
	switch (proctal_error(p)) {
	case PROCTAL_ERROR_PERMISSION_DENIED:
		fprintf(stderr, "No permission to read from address ");
		cli_val_print(address, stderr);
		fprintf(stderr, ".\n");
		return 1;

	default:
		fprintf(stderr, "Failed to read from address ");
		cli_val_print(address, stderr);
		fprintf(stderr, ".\n");
		return 1;
	}

	if (!proctal_error_recover(p)) {
		return 0;
	}
}

/*
 * Matches against the output of a previous run.
 *
 * Returns 0 on failure, 1 on success.
 */
static inline int search_input(struct cli_cmd_search_arg *arg, proctal_t p)
{
	int ret = 0;

	struct cli_val_filter_compare_arg *filter_compare_arg = create_filter_compare_arg(arg);
	struct cli_val_filter_compare_prev_arg *filter_compare_prev_arg = create_filter_compare_prev_arg(arg);

	cli_val_t address = cli_val_wrap(CLI_VAL_TYPE_ADDRESS, cli_val_address_create());
	cli_val_t value = arg->value;
	cli_val_t previous_value = cli_val_create_clone(value);

	void *address_start = arg->address_start;
	void *address_stop = arg->address_stop == NULL ? (char *) ~((uintptr_t) 0) : arg->address_stop;

	for (;;) {
		cli_scan_skip_chars(stdin, "\n ");

		if (feof(stdin)) {
			// It's over.
			break;
		}

		if (handle_parse_input_error(parse_input(address, previous_value), address)) {
			continue;
		}

		if (DEREF(void *, cli_val_data(address)) < address_start
			|| DEREF(void *, cli_val_data(address)) >= address_stop) {
			// Out of range.
			continue;
		}

		size_t size = cli_val_sizeof(previous_value);

		if (proctal_read(p, DEREF(void *, cli_val_data(address)), cli_val_data(value), size) != size) {
			if (!handle_proctal_read_previous_error(p, address)) {
				goto exit2;
			}

			continue;
		}

		if (!cli_val_filter_compare(filter_compare_arg, value)) {
			continue;
		}

		if (!cli_val_filter_compare_prev(filter_compare_prev_arg, value, previous_value)) {
			continue;
		}

		print_search_match(address, value);
	}

	ret = 1;
exit2:
	cli_val_destroy(address);
	cli_val_destroy(previous_value);
exit1:
	destroy_filter_compare_prev_arg(filter_compare_prev_arg);
	destroy_filter_compare_arg(filter_compare_arg);
exit0:
	return ret;
}

/*
 * Configures Proctal based on the arguments passed.
 */
void setup_proctal(struct cli_cmd_search_arg *arg, proctal_t p)
{
	proctal_pid_set(p, arg->pid);

	if (!arg->read && !arg->write && !arg->execute) {
		// By default will search readable memory.
		proctal_scan_address_read_set(p, 1);
		proctal_scan_address_write_set(p, 0);
		proctal_scan_address_execute_set(p, 0);

		proctal_scan_region_read_set(p, 1);
		proctal_scan_region_write_set(p, 0);
		proctal_scan_region_execute_set(p, 0);
	} else {
		proctal_scan_address_read_set(p, arg->read);
		proctal_scan_address_write_set(p, arg->write);
		proctal_scan_address_execute_set(p, arg->execute);

		proctal_scan_region_read_set(p, arg->read);
		proctal_scan_region_write_set(p, arg->write);
		proctal_scan_region_execute_set(p, arg->execute);
	}

	proctal_scan_address_region_set(p, arg->region);
	proctal_scan_region_mask_set(p, arg->region);
}

int cli_cmd_search(struct cli_cmd_search_arg *arg)
{
	int ret = 1;

	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit1;
	}

	setup_proctal(arg, p);

	if (arg->pause) {
		proctal_pause(p);

		if (proctal_error(p)) {
			cli_print_proctal_error(p);
			goto exit1;
		}
	}

	if (arg->review) {
		if (!search_input(arg, p)) {
			goto exit2;
		}
	} else {
		if (!search_program(arg, p)) {
			goto exit2;
		}
	}

	ret = 0;
exit2:
	if (arg->pause) {
		proctal_resume(p);
	}
exit1:
	proctal_close(p);
exit0:
	return ret;
}

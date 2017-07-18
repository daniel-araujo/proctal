#include <string.h>
#include <assert.h>

#include "cli/cmd/pattern.h"
#include "cli/printer.h"
#include "cli/scanner.h"
#include "api/include/proctal.h"
#include "swbuf/swbuf.h"
#include "chunk/chunk.h"

static void print_match(void *addr)
{
	cli_print_address(addr);
	printf("\n");
}

int cli_cmd_pattern(struct cli_cmd_pattern_arg *arg)
{
	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_close(p);
		return 1;
	}

	proctal_pid_set(p, arg->pid);

	if (arg->freeze) {
		proctal_freeze(p);

		if (proctal_error(p)) {
			cli_print_proctal_error(p);
			proctal_close(p);
			return 1;
		}
	}

	if (!arg->read && !arg->write && !arg->execute) {
		// By default will search readable memory.
		proctal_scan_region_read_set(p, 1);
		proctal_scan_region_write_set(p, 0);
		proctal_scan_region_execute_set(p, 0);
	} else {
		proctal_scan_region_read_set(p, arg->read);
		proctal_scan_region_write_set(p, arg->write);
		proctal_scan_region_execute_set(p, arg->execute);
	}

	long mask = 0;

	if (arg->program_code) {
		mask |= PROCTAL_REGION_PROGRAM_CODE;
	}

	proctal_scan_region_mask_set(p, mask);

	proctal_scan_region_start(p);

	cli_pattern cp = cli_pattern_create();
	cli_pattern_compile(cp, arg->pattern);

	if (cli_pattern_error(cp)) {
		cli_print_pattern_error(cp);
		cli_pattern_destroy(cp);
		proctal_scan_region_stop(p);
		proctal_close(p);
		return 1;
	}

	const size_t buffer_size = 1024 * 1024;
	struct swbuf buf;
	swbuf_init(&buf, buffer_size);

	size_t prev_size, curr_size;
	void *start, *end;

	struct chunk chunk;

	while (proctal_scan_region(p, &start, &end)) {
		// Starting address of the matching pattern.
		char *pattern_start = start;
		cli_pattern_new(cp);

		chunk_init(&chunk, start, end, buffer_size);

		do {
			char *offset = chunk_offset(&chunk);
			curr_size = chunk_size(&chunk);

			proctal_read(p, offset, swbuf_address_offset(&buf, 0), curr_size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);

				proctal_error_recover(p);

				// Since we cannot read this chunk of memory
				// we're going to discard any progress there
				// might have been made in the previous chunk.
				break;
			}

			// Remaining characters to read in the current chunk.
			size_t remaining = curr_size;

			while (remaining) {
				size_t read = cli_pattern_input(cp, swbuf_address_offset(&buf, curr_size - remaining), remaining);

				if (cli_pattern_finished(cp)) {
					if (cli_pattern_matched(cp)) {
						print_match(pattern_start);

						cli_pattern_new(cp);
						remaining -= read;

						if (pattern_start < offset) {
							// Count reads from
							// previous chunk.
							read += offset - pattern_start;
						}

						pattern_start = pattern_start + read;
					} else {
						cli_pattern_new(cp);

						if (pattern_start < offset) {
							// The pattern match
							// started in the
							// previous chunk.
							// We're going to have
							// to backtrack.

							// Start at the next
							// character now.
							pattern_start += 1;

							// This calculation can
							// result in a 0 when
							// pattern_start equals
							// offset but
							// that will do no harm
							// because it's going
							// to do nothing.
							size_t prev_remaining = offset - pattern_start;

							assert(prev_remaining < buffer_size);

							cli_pattern_input(cp, swbuf_address_offset(&buf, prev_size - prev_remaining - buffer_size), prev_remaining);
						} else {
							// Start at the next
							// character now.
							pattern_start += 1;

							remaining -= 1;
						}
					}
				} else {
					// Read to the end of the buffer but
					// wasn't enough.
					remaining -= read;
				}
			}

			swbuf_swap(&buf);

			// Remembering the size of the previous chunk.
			prev_size = curr_size;
		} while (chunk_next(&chunk));
	}

	swbuf_deinit(&buf);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		cli_pattern_destroy(cp);
		proctal_scan_region_stop(p);

		if (arg->freeze) {
			proctal_unfreeze(p);
		}

		proctal_close(p);
		return 1;
	}

	cli_pattern_destroy(cp);

	proctal_scan_region_stop(p);

	if (arg->freeze) {
		proctal_unfreeze(p);
	}

	proctal_close(p);

	return 0;
}

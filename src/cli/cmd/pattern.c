#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "cli/cmd/pattern.h"
#include "cli/printer.h"
#include "cli/scanner.h"
#include "api/include/proctal.h"
#include "swbuf/swbuf.h"
#include "chunk/chunk.h"

static void print_match(void *address)
{
	cli_print_address(address);
	printf("\n");
}

int cli_cmd_pattern(struct cli_cmd_pattern_arg *arg)
{
	int ret = 1;

	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit1;
	}

	proctal_pid_set(p, arg->pid);

	if (arg->pause) {
		proctal_pause(p);

		if (proctal_error(p)) {
			cli_print_proctal_error(p);
			goto exit1;
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

	proctal_scan_region_mask_set(p, arg->region);

	proctal_scan_region_start(p);

	cli_pattern cp = cli_pattern_create();
	cli_pattern_compile(cp, arg->pattern);

	if (cli_pattern_error(cp)) {
		cli_print_pattern_error(cp);
		goto exit4;
	}

	void *address_start = arg->address_start;
	void *address_stop = arg->address_stop == NULL ? (char *) ~((uintptr_t) 0) : arg->address_stop;

	const size_t buffer_size = 1024 * 1024;
	struct swbuf buf;
	swbuf_init(&buf, buffer_size);

	size_t prev_size, curr_size;
	void *start, *end;

	struct chunk chunk;

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

		// Starting address of the matching pattern.
		char *pattern_start = start;
		cli_pattern_new(cp);

		chunk_init(&chunk, start, end, buffer_size);

		prev_size = 0;

		do {
			char *offset = chunk_offset(&chunk);
			curr_size = chunk_size(&chunk);

			proctal_read(p, offset, swbuf_offset(&buf, 0), curr_size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);

				if (!proctal_error_recover(p)) {
					goto exit5;
				}

				// Since we cannot read this chunk of memory
				// we're going to discard any progress there
				// might have been made in the previous chunk.
				break;
			}

			// Remaining characters to read in the current chunk.
			size_t remaining = curr_size;

			while (remaining) {
				size_t read = cli_pattern_input(cp, swbuf_offset(&buf, curr_size - remaining), remaining);

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

							cli_pattern_input(cp, swbuf_offset(&buf, prev_size - prev_remaining - buffer_size), prev_remaining);
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

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit5;
	}

	ret = 0;
exit5:
	swbuf_deinit(&buf);
exit4:
	cli_pattern_destroy(cp);
exit3:
	proctal_scan_region_stop(p);
exit2:
	if (arg->pause) {
		proctal_resume(p);
	}
exit1:
	proctal_close(p);
exit0:
	return ret;
}

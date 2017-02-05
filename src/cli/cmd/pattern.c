#include <string.h>
#include <assert.h>

#include "lib/include/proctal.h"
#include "swbuf/swbuf.h"
#include "cli/cmd.h"
#include "cli/printer.h"
#include "cli/scanner.h"

static void print_match(void *addr)
{
	cli_print_address(addr);
	printf("\n");
}

int cli_cmd_pattern(struct cli_cmd_pattern_arg *arg)
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
		proctal_region_set_read(p, 1);
		proctal_region_set_write(p, 0);
		proctal_region_set_execute(p, 0);
	} else {
		proctal_region_set_read(p, arg->read);
		proctal_region_set_write(p, arg->write);
		proctal_region_set_execute(p, arg->execute);
	}

	long mask = 0;

	if (arg->program_code) {
		mask |= PROCTAL_REGION_PROGRAM_CODE;
	}

	proctal_region_set_mask(p, mask);

	proctal_region_new(p);

	cli_pattern cp = cli_pattern_create();
	cli_pattern_compile(cp, arg->pattern);

	if (cli_pattern_error(cp)) {
		cli_print_pattern_error(cp);
		cli_pattern_destroy(cp);
		proctal_destroy(p);
		return 1;
	}

	const size_t buffer_size = 1024 * 1024;
	struct swbuf buf;
	swbuf_init(&buf, buffer_size);

	size_t prev_size, curr_size;
	void *start, *end;

	while (proctal_region(p, &start, &end)) {
		// Starting address of the matching pattern.
		char *pattern_start = start;
		cli_pattern_new(cp);

		for (size_t chunk = 0;; ++chunk) {
			// This is the starting address of the current chunk.
			char *chunk_offset = (char *) start + buffer_size * chunk;

			if (chunk_offset >= (char *) end) {
				// We'd be going past the end so we're going to
				// discard any progress made until now and go
				// to the next region.
				break;
			}

			// Going to attempt to read everything to the end...
			curr_size = (char *) end - chunk_offset;

			if (curr_size > buffer_size) {
				// Cannot copy everything to the end. Limited
				// to our buffer size. We'll get the remaining
				// stuff in the next chunk.
				curr_size = buffer_size;
			}

			proctal_read(p, chunk_offset, swbuf_address_offset(&buf, 0), curr_size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);

				proctal_error_ack(p);

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

						if (pattern_start < chunk_offset) {
							// Count reads from
							// previous chunk.
							read += chunk_offset - pattern_start;
						}

						pattern_start = pattern_start + read;
					} else {
						cli_pattern_new(cp);

						if (pattern_start < chunk_offset) {
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
							// chunk_offset but
							// that will do no harm
							// because it's going
							// to do nothing.
							size_t prev_remaining = chunk_offset - pattern_start;

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
		}
	}

	swbuf_deinit(&buf);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		cli_pattern_destroy(cp);
		proctal_destroy(p);
		return 1;
	}

	cli_pattern_destroy(cp);
	proctal_destroy(p);

	return 0;
}

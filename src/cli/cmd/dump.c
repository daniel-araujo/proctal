#include <stdio.h>
#include <stdint.h>

#include "cli/cmd/dump.h"
#include "cli/printer.h"
#include "api/include/proctal.h"
#include "chunk/chunk.h"

int cli_cmd_dump(struct cli_cmd_dump_arg *arg)
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
		// By default will dump everything.
		proctal_scan_region_read_set(p, 0);
		proctal_scan_region_write_set(p, 0);
		proctal_scan_region_execute_set(p, 0);
	} else {
		proctal_scan_region_read_set(p, arg->read);
		proctal_scan_region_write_set(p, arg->write);
		proctal_scan_region_execute_set(p, arg->execute);
	}

	if (arg->address_stop == NULL) {
		arg->address_stop = (void *) ~((uintptr_t) 0);
	}

	proctal_scan_region_mask_set(p, arg->region);

	proctal_scan_region_start(p);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit2;
	}

	const size_t output_block_size = 1024 * 1024 * 2;
	unsigned char *output_block = malloc(output_block_size);

	if (output_block == NULL) {
		fprintf(stderr, "Not enough memory.");
		goto exit3;
	}

	void *start, *end;

	struct chunk chunk;

	while (proctal_scan_region_next(p, &start, &end)) {
		if (start < arg->address_start) {
			// We can start from here.
			start = arg->address_start;
		}

		if (end > arg->address_stop) {
			// We can end here.
			end = arg->address_stop;
		}

		if (start >= end) {
			// Out of range. Try next region.
			continue;
		}

		chunk_init(&chunk, start, end, output_block_size);

		do {
			char *offset = chunk_offset(&chunk);
			size_t size = chunk_size(&chunk);

			proctal_read(p, offset, output_block, size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);

				if (!proctal_error_recover(p)) {
					goto exit4;
				}

				// Let's try the next chunk.
				continue;
			}

			fwrite(output_block, 1, size, stdout);
		} while (chunk_next(&chunk));
	}

	ret = 0;
exit4:
	free(output_block);
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

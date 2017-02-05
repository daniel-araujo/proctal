#include "lib/include/proctal.h"
#include "cli/cmd.h"
#include "cli/printer.h"

int cli_cmd_dump(struct cli_cmd_dump_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	if (!arg->read && !arg->write && !arg->execute) {
		// By default will dump everything.
		proctal_region_set_read(p, 0);
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

	const size_t output_block_size = 1024 * 1024 * 2;
	char *output_block = malloc(output_block_size);

	void *start, *end;

	while (proctal_region(p, &start, &end)) {
		for (size_t chunk = 0;; ++chunk) {
			// This is the starting address of the current chunk.
			char *chunk_offset = (char *) start + output_block_size * chunk;

			if (chunk_offset >= (char *) end) {
				// Went past the end of this region.
				break;
			}

			size_t chunk_size = (char *) end - chunk_offset;

			if (chunk_size > output_block_size) {
				chunk_size = output_block_size;
			}

			proctal_read(p, chunk_offset, output_block, chunk_size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);

				proctal_error_ack(p);

				// Let's try the next chunk.
				continue;
			}

			fwrite(output_block, 1, chunk_size, stdout);
		}
	}

	free(output_block);

	proctal_destroy(p);

	return 0;
}

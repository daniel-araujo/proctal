#include <stdio.h>

#include "cli/cmd/dump.h"
#include "cli/printer.h"
#include "api/include/proctal.h"
#include "chunk/chunk.h"

int cli_cmd_dump(struct cli_cmd_dump_arg *arg)
{
	proctal_t p = proctal_create();

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

	struct chunk chunk;

	while (proctal_region(p, &start, &end)) {
		chunk_init(&chunk, start, end, output_block_size);

		do {
			char *offset = chunk_offset(&chunk);
			size_t size = chunk_size(&chunk);

			proctal_read(p, offset, output_block, size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);

				proctal_error_ack(p);

				// Let's try the next chunk.
				continue;
			}

			fwrite(output_block, 1, size, stdout);
		} while (chunk_next(&chunk));
	}

	free(output_block);

	proctal_destroy(p);

	return 0;
}

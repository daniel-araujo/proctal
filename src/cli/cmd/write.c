#include <unistd.h>

#include "cli/cmd/write.h"
#include "cli/printer.h"
#include "api/include/proctal.h"

int cli_cmd_write(struct cli_cmd_write_arg *arg)
{
	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_close(p);
		return 1;
	}

	proctal_pid_set(p, arg->pid);

	do {
		size_t list_size = cli_val_list_size(arg->value_list);
		char *address = (char *) arg->address;

		for (size_t i = 0, j = 0; i < arg->array; ++i, ++j) {
			if (j == list_size) {
				j = 0;
			}

			cli_val v = cli_val_list_get(arg->value_list, j);

			size_t size = cli_val_sizeof(v);
			char *input = cli_val_data(v);

			proctal_write(p, address, input, size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);
				proctal_close(p);
				return 1;
			}

			address += size;
		}

		if (arg->repeat && arg->repeat_delay > 0) {
			usleep(arg->repeat_delay * 1000);
		}
	} while (arg->repeat);

	proctal_close(p);

	return 0;
}

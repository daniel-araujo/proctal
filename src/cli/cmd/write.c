#include <unistd.h>

#include "cli/cmd/write.h"
#include "cli/printer.h"
#include "api/include/proctal.h"

int cli_cmd_write(struct cli_cmd_write_arg *arg)
{
	int ret = 1;

	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit1;
	}

	proctal_pid_set(p, arg->pid);

	if (arg->freeze) {
		proctal_freeze(p);

		if (proctal_error(p)) {
			cli_print_proctal_error(p);
			goto exit1;
		}
	}

	do {
		size_t list_size = darr_size(&arg->values);
		char *address = (char *) arg->address;

		for (size_t i = 0, j = 0; i < arg->array; ++i, ++j) {
			if (j == list_size) {
				j = 0;
			}

			cli_val *v = darr_element(&arg->values, j);

			size_t size = cli_val_sizeof(*v);
			void *input = cli_val_data(*v);

			proctal_write(p, address, input, size);

			if (proctal_error(p)) {
				cli_print_proctal_error(p);
				goto exit2;
			}

			address += size;
		}

		if (arg->repeat && arg->repeat_delay > 0) {
			usleep(arg->repeat_delay * 1000);
		}
	} while (arg->repeat);

	ret = 0;
exit2:
	if (arg->freeze) {
		proctal_unfreeze(p);
	}
exit1:
	proctal_close(p);
exit0:
	return ret;
}

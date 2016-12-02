#include <unistd.h>
#include <proctal.h>

#include "cmd.h"
#include "printer.h"

int proctal_cmd_write(struct proctal_cmd_write_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		proctal_print_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	do {
		proctal_cmd_val *v = arg->first_value;
		char *addr = (char *) arg->address;
		for (size_t i = 0; i < arg->array; ++i) {
			if (v == arg->end_value) {
				v = arg->first_value;
			}

			size_t size = proctal_cmd_val_sizeof(*v);
			char *input = proctal_cmd_val_addr(*v);

			proctal_write(p, addr, input, size);

			if (proctal_error(p)) {
				proctal_print_error(p);
				proctal_destroy(p);
				return 1;
			}

			v += 1;
			addr += size;
		}

		if (arg->repeat && arg->repeat_delay > 0) {
			usleep(arg->repeat_delay * 1000);
		}
	} while (arg->repeat);

	proctal_destroy(p);

	return 0;
}

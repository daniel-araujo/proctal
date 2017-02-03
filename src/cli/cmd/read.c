#include <proctal.h>

#include "cmd.h"
#include "printer.h"

static inline void print_separator(struct cli_cmd_read_arg *arg)
{
	switch (cli_val_type(arg->value)) {
	case CLI_VAL_TYPE_TEXT:
		break;

	case CLI_VAL_TYPE_BYTE:
		printf(" ");
		break;
	case CLI_VAL_TYPE_INTEGER:
	case CLI_VAL_TYPE_IEEE754:
	case CLI_VAL_TYPE_ADDRESS:
	default:
		printf("\n");
		break;
	}
}

static inline void print_ending(struct cli_cmd_read_arg *arg)
{
	printf("\n");
}

int cli_cmd_read(struct cli_cmd_read_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	char output[16];

	char *addr = (char *) arg->address;
	for (size_t i = 0; i < arg->array; ++i) {
		proctal_read(p, addr, output, sizeof output / sizeof output[0]);

		switch (proctal_error(p)) {
		case 0:
			break;

		default:
			cli_print_proctal_error(p);
			proctal_destroy(p);
			return 1;
		}

		cli_val_set_address(arg->value, addr);

		int size = cli_val_parse_bin(arg->value, output, sizeof output / sizeof output[0]);

		if (size == 0) {
			if (i == 0) {
				fprintf(stderr, "Failed to parse value.\n");
			} else {
				fprintf(stderr, "Failed to parse further values.\n");
			}

			proctal_destroy(p);
			return 1;
		}

		if (arg->show_instruction_address
			&& cli_val_type(arg->value) == CLI_VAL_TYPE_INSTRUCTION) {
			cli_print_address(addr);
			printf("\t");
		}

		addr += size;

		cli_val_print(arg->value, stdout);

		if (arg->show_instruction_byte_code
			&& cli_val_type(arg->value) == CLI_VAL_TYPE_INSTRUCTION) {
			printf("\n");

			if (arg->show_instruction_address) {
				printf("\t");
			}

			for (int j = 0; j < size; j++) {
				cli_print_byte(output[j]);

				if (j < size - 1) {
					printf(" ");
				}
			}
		}

		if (i < arg->array - 1) {
			print_separator(arg);
		}
	}

	print_ending(arg);

	proctal_destroy(p);

	return 0;
}

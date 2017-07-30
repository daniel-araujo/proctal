#include "cli/cmd/read.h"
#include "cli/printer.h"
#include "api/include/proctal.h"
#include "magic/magic.h"

static inline void print_separator(struct cli_cmd_read_arg *arg)
{
	if (arg->show_address) {
		printf("\n");
		return;
	}

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

	char output[16];

	char *addr = (char *) arg->address;
	for (size_t i = 0; i < arg->array; ++i) {
		proctal_read(p, addr, output, ARRAY_SIZE(output));

		switch (proctal_error(p)) {
		case 0:
			break;

		default:
			cli_print_proctal_error(p);

			if (arg->freeze) {
				proctal_unfreeze(p);
			}

			proctal_close(p);
			return 1;
		}

		cli_val_address_set(arg->value, addr);

		int size = cli_val_parse_bin(arg->value, output, ARRAY_SIZE(output));

		if (size == 0) {
			if (i == 0) {
				fprintf(stderr, "Failed to parse value.\n");
			} else {
				fprintf(stderr, "Failed to parse further values.\n");
			}

			if (arg->freeze) {
				proctal_unfreeze(p);
			}

			proctal_close(p);
			return 1;
		}

		if (arg->show_address) {
			cli_print_address(addr);
			printf("\t");
		}

		cli_val_print(arg->value, stdout);

		if (arg->show_instruction_bytecode
			&& cli_val_type(arg->value) == CLI_VAL_TYPE_INSTRUCTION) {
			printf("\n");

			if (arg->show_address) {
				printf("\t");
			}

			for (int j = 0; j < size; j++) {
				cli_print_byte(output[j]);

				if (j < size - 1) {
					printf(" ");
				}
			}

			// Rely on the separator being a new line.
		}

		if (i < arg->array - 1) {
			print_separator(arg);
		}

		addr += size;
	}

	print_ending(arg);

	if (arg->freeze) {
		proctal_unfreeze(p);
	}

	proctal_close(p);

	return 0;
}

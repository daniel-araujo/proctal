#include "cli/cmd/read.h"
#include "cli/printer.h"
#include "api/include/proctal.h"
#include "magic/magic.h"

typedef void (*printer_t)(struct cli_cmd_read_arg *arg, void *address, size_t i);

/*
 * Prints the separator between values.
 */
static inline void print_text_separator(struct cli_cmd_read_arg *arg)
{
	if (arg->show_address || arg->show_bytes) {
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

/*
 * Prints the ending.
 */
static inline void print_text_ending(struct cli_cmd_read_arg *arg)
{
	printf("\n");
}

/*
 * Prints the value as text.
 */
static inline void print_text(struct cli_cmd_read_arg *arg, void *address, size_t i)
{
	unsigned char *data = cli_val_data(arg->value);
	size_t size = cli_val_sizeof(arg->value);

	if (arg->show_address) {
		cli_print_address(address);
		printf("\t");
	}

	cli_val_print(arg->value, stdout);

	if (arg->show_bytes) {
		printf("\n\t");

		for (size_t j = 0; j < size; j++) {
			cli_print_byte(data[j]);

			if (j < size - 1) {
				printf(" ");
			}
		}

		// Rely on the separator being a new line.
	}

	if (i < arg->array - 1) {
		print_text_separator(arg);
	} else {
		print_text_ending(arg);
	}
}

/*
 * Prints the value as binary.
 */
static inline void print_binary(struct cli_cmd_read_arg *arg, void *address, size_t i)
{
	unsigned char *data = cli_val_data(arg->value);
	size_t size = cli_val_sizeof(arg->value);

	fwrite(data, 1, size, stdout);
}

int cli_cmd_read(struct cli_cmd_read_arg *arg)
{
	int ret = 0;

	printer_t print = arg->binary ? print_binary : print_text;

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

	unsigned char output[16];

	char *address = (char *) arg->address;
	for (size_t i = 0; i < arg->array; ++i) {
		proctal_read(p, address, output, ARRAY_SIZE(output));

		if (proctal_error(p)) {
			cli_print_proctal_error(p);
			goto exit2;
		}

		cli_val_address_set(arg->value, address);

		int size = cli_val_parse_binary(arg->value, output, ARRAY_SIZE(output));

		if (size == 0) {
			if (i == 0) {
				fprintf(stderr, "Failed to parse value.\n");
			} else {
				fprintf(stderr, "Failed to parse further values.\n");
			}

			goto exit2;
		}

		print(arg, address, i);

		address += size;
	}

	ret = 1;
exit2:
	if (arg->pause) {
		proctal_resume(p);
	}
exit1:
	proctal_close(p);
exit0:
	return ret;
}

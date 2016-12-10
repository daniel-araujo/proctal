#include <string.h>
#include <proctal.h>

#include "cmd.h"
#include "printer.h"
#include "scanner.h"

static void print_match(void *addr)
{
	static cli_val v = NULL;

	if (v == NULL) {
		cli_val_attr addr_attr = cli_val_attr_create(CLI_VAL_TYPE_ADDRESS);
		v = cli_val_create(addr_attr);
		cli_val_attr_destroy(addr_attr);
	}

	cli_val_parse_bin(v, (const char *) &addr, sizeof addr);

	cli_val_print(v, stdout);
	printf("\n");
}

int cli_cmd_pattern(struct cli_cmd_pattern_arg *arg)
{
	fprintf(stderr, "To be implemented\n");
	return 1;

	proctal p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	proctal_address_set_read(p, arg->read);
	proctal_address_set_write(p, arg->write);
	proctal_address_set_execute(p, arg->execute);

	proctal_address_new(p);

	cli_pattern cp = cli_pattern_create();
	cli_pattern_compile(cp, arg->pattern);

	if (cli_pattern_error(cp)) {
		cli_print_pattern_error(cp);
		cli_pattern_destroy(cp);
		proctal_destroy(p);
		return 1;
	}

	void *addr;

	while (proctal_address(p, &addr)) {
		char ch;

		proctal_read(p, addr, &ch, 1);

		if (proctal_error(p)) {
			cli_print_proctal_error(p);
			cli_pattern_destroy(cp);
			proctal_destroy(p);
			return 1;
		}

		cli_pattern_input(cp, &ch, 1);

		if (cli_pattern_error(cp)) {
			cli_print_pattern_error(cp);
			cli_pattern_destroy(cp);
			proctal_destroy(p);
			return 1;
		}

		if (cli_pattern_finished(cp)) {
			if (cli_pattern_matched(cp)) {
				print_match(addr);
			}

			cli_pattern_new(cp);
		}
	}

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

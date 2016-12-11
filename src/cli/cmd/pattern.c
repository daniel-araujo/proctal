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
	proctal p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	if (!arg->read && !arg->write && !arg->execute) {
		// By default will search readable memory.
		proctal_address_set_read(p, 1);
		proctal_address_set_write(p, 0);
		proctal_address_set_execute(p, 0);
	} else {
		proctal_address_set_read(p, arg->read);
		proctal_address_set_write(p, arg->write);
		proctal_address_set_execute(p, arg->execute);
	}

	long mask = 0;

	if (arg->program_code) {
		mask |= PROCTAL_ADDR_REGION_PROGRAM_CODE;
	}

	proctal_address_set_region(p, mask);

	proctal_address_new(p);

	cli_pattern cp = cli_pattern_create();
	cli_pattern_compile(cp, arg->pattern);

	if (cli_pattern_error(cp)) {
		cli_print_pattern_error(cp);
		cli_pattern_destroy(cp);
		proctal_destroy(p);
		return 1;
	}

	void *start = NULL;
	void *prev = NULL;
	void *curr;
	int is_linear = 1;

	while (proctal_address(p, &curr)) {
		if (start == NULL) {
			start = curr;
			is_linear = 1;
		} else if (prev != (char *) curr - 1) {
			is_linear = 0;
		}

		char ch;

		proctal_read(p, curr, &ch, 1);

		if (proctal_error(p)) {
			proctal_error_ack(p);
			cli_pattern_new(cp);
			start = NULL;
			prev = NULL;
			break;
		}

		cli_pattern_input(cp, &ch, 1);

		if (cli_pattern_finished(cp)) {
			if (cli_pattern_matched(cp)) {
				print_match(start);
			}

			cli_pattern_new(cp);

			if (is_linear && start != curr) {
				start = (char *) start + 1;

				for (void *backtrack = start;; backtrack = (char *) backtrack + 1) {
					proctal_read(p, backtrack, &ch, 1);
					cli_pattern_input(cp, &ch, 1);

					if (backtrack == curr) {
						break;
					}
				}
			} else {
				start = NULL;
			}
		}

		prev = curr;
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

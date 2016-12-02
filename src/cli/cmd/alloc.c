#include <proctal.h>

#include "cmd.h"
#include "printer.h"

static int make_permission(struct cli_cmd_alloc_arg *arg)
{
	int perm = 0;

	if (arg->read) {
		perm |= PROCTAL_ALLOC_PERM_READ;
	}

	if (arg->write) {
		perm |= PROCTAL_ALLOC_PERM_WRITE;
	}

	if (arg->execute) {
		perm |= PROCTAL_ALLOC_PERM_EXECUTE;
	}

	return perm;
}

int cli_cmd_alloc(struct cli_cmd_alloc_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	int perm = make_permission(arg);

	void *addr = proctal_alloc(p, arg->size, perm);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	cli_val_attr addr_attr = cli_val_attr_create(CLI_VAL_TYPE_ADDRESS);
	cli_val vaddr = cli_val_create(addr_attr);
	cli_val_attr_destroy(addr_attr);
	cli_val_parse_bin(vaddr, (const char *) &addr, sizeof addr);
	cli_val_print(vaddr, stdout);
	cli_val_destroy(vaddr);
	printf("\n");

	proctal_destroy(p);

	return 0;
}

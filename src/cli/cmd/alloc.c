#include <proctal.h>

#include "cmd.h"
#include "printer.h"

static int make_permission(struct proctal_cmd_alloc_arg *arg)
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

int proctal_cmd_alloc(struct proctal_cmd_alloc_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		proctal_print_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	int perm = make_permission(arg);

	void *addr = proctal_alloc(p, arg->size, perm);

	if (proctal_error(p)) {
		proctal_print_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_cmd_val_attr addr_attr = proctal_cmd_val_attr_create(PROCTAL_CMD_VAL_TYPE_ADDRESS);
	proctal_cmd_val vaddr = proctal_cmd_val_create(addr_attr);
	proctal_cmd_val_attr_destroy(addr_attr);
	proctal_cmd_val_parse_bin(vaddr, (const char *) &addr, sizeof addr);
	proctal_cmd_val_print(vaddr, stdout);
	proctal_cmd_val_destroy(vaddr);
	printf("\n");

	proctal_destroy(p);

	return 0;
}

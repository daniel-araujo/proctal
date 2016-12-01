#include <proctal.h>

#include "cmd.h"

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

	switch (proctal_error(p)) {
	case 0:
		break;

	case PROCTAL_ERROR_OUT_OF_MEMORY:
		fprintf(stderr, "Out of memory.\n");
		proctal_destroy(p);
		return 1;

	default:
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	int perm = make_permission(arg);

	void *addr = proctal_alloc(p, arg->size, perm);

	switch (proctal_error(p)) {
	case 0:
		break;

	case PROCTAL_ERROR_PERMISSION_DENIED:
		fprintf(stderr, "Permission denied.\n");
		proctal_destroy(p);
		return 1;

	case PROCTAL_ERROR_PROCESS_NOT_FOUND:
		fprintf(stderr, "Process not found.\n");
		proctal_destroy(p);
		return 1;

	default:
		fprintf(stderr, "Failed to cleanup properly.\n");
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

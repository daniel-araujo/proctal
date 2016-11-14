#include <proctal.h>

#include "cmd.h"

int proctal_cmd_watch(struct proctal_cmd_watch_arg *arg)
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

	if (!arg->read && !arg->write) {
		fprintf(stderr, "Did not specify what to watch for.\n");
		proctal_destroy(p);
		return 1;
	}

	if (arg->read && !arg->write) {
		fprintf(stderr, "Watching for reads only is not supported yet.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	proctal_watch pw = proctal_watch_create(p);

	if (proctal_error(p)) {
		fprintf(stderr, "Failed to create watch.\n");
	}

	proctal_watch_set_addr(pw, arg->address);
	proctal_watch_set_read(pw, arg->read);
	proctal_watch_set_write(pw, arg->write);

	void *addr;

	proctal_watch_next(pw, &addr);

	printf("%p\n", addr);

	proctal_destroy(p);

	return 0;
}

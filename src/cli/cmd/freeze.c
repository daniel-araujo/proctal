#include <unistd.h>
#include <proctal.h>

#include "cmd.h"

int proctal_cmd_freeze(struct proctal_cmd_freeze_arg *arg)
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

	if (!proctal_freeze(p)) {
		switch (proctal_error(p)) {
		case 0:
			break;

		case PROCTAL_ERROR_PERMISSION_DENIED:
			fprintf(stderr, "Permission denied.\n");
			proctal_destroy(p);
			return 1;

		default:
			fprintf(stderr, "Unable to freeze.\n");
			proctal_destroy(p);
			return 1;
		}
	}

	while (getchar() != EOF);

	proctal_unfreeze(p);

	proctal_destroy(p);

	return 0;
}

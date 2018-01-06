#include <stdio.h>
#include <errno.h>

#include "cli/cmd/pause.h"
#include "cli/printer.h"
#include "api/include/proctal.h"
#include "pq/pq.h"

int cli_cmd_pause(struct cli_cmd_pause_arg *arg)
{
	int ret = 1;

	if (!pq_start()) {
		fprintf(stderr, "Failed to start tracking quit signals.\n");
		goto exit0;
	}

	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit2;
	}

	proctal_pid_set(p, arg->pid);

	proctal_pause(p);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit2;
	}

	pq_wait();

	proctal_resume(p);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit2;
	}

	ret = 0;
exit2:
	proctal_close(p);
exit1:
	pq_stop();
exit0:
	return ret;
}

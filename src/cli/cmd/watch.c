#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <darr.h>

#include "cli/cmd/watch.h"
#include "cli/printer.h"
#include "api/include/proctal.h"
#include "magic/magic.h"

static int request_quit = 0;

static void quit(int signum)
{
	request_quit = 1;
}

static int register_signal_handler()
{
	struct sigaction sa = {
		.sa_handler = quit,
		.sa_flags = 0,
	};

	sigemptyset(&sa.sa_mask);

	return sigaction(SIGINT, &sa, NULL) != -1
		&& sigaction(SIGTERM, &sa, NULL) != -1;
}

static void unregister_signal_handler()
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

int cli_cmd_watch(struct cli_cmd_watch_arg *arg)
{
	int ret = 1;

	if (!register_signal_handler()) {
		fprintf(stderr, "Failed to set up signal handler.\n");
		goto exit0;
	}

	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit2;
	}

	if (!arg->read && !arg->write && !arg->execute) {
		fprintf(stderr, "Did not specify what to watch for.\n");
		goto exit2;
	}

	if (!(arg->read && arg->write && !arg->execute)
		&& !(arg->write && !arg->read && !arg->execute)
		&& !(!arg->write && !arg->read && arg->execute)) {
		fprintf(stderr, "The given combination of read, write and execute options is not supported.\n");
		goto exit2;
	}

	proctal_pid_set(p, arg->pid);

	proctal_watch_address_set(p, arg->address);
	proctal_watch_read_set(p, arg->read);
	proctal_watch_write_set(p, arg->write);
	proctal_watch_execute_set(p, arg->execute);

	// TODO: Should use a data structure with better lookup performance.
	struct darr matches;
	darr_init(&matches, sizeof(void *));

	if (!darr_resize(&matches, 42)) {
		fprintf(stderr, "Out of memory.\n");
		goto exit3;
	}

	size_t match_count = 0;

	proctal_watch_start(p);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit3;
	}

	while (!request_quit) {
		void *addr;

		if (!proctal_watch(p, &addr)) {
			switch (proctal_error(p)) {
			case 0:
				continue;

			case PROCTAL_ERROR_INTERRUPT:
				if (!proctal_error_recover(p)) {
					goto exit4;
				}
				continue;

			default:
				cli_print_proctal_error(p);
				goto exit4;
			}
		}

		if (arg->unique) {
			int match = 0;

			for (size_t i = 0; i < match_count; ++i) {
				void **prev = darr_element(&matches, i);

				if (addr == *prev) {
					match = 1;
					break;
				}
			}

			if (match) {
				continue;
			} else {
				match_count += 1;

				if (match_count > darr_size(&matches)) {
					// We're out of space. Let's double it.
					darr_resize(&matches, darr_size(&matches) * 2);
				}

				void **e = darr_element(&matches, match_count - 1);
				*e = addr;
			}
		}

		cli_print_address(addr);
		printf("\n");
	}

	ret = 0;
exit4:
	proctal_watch_stop(p);
exit3:
	darr_deinit(&matches);
exit2:
	proctal_close(p);
exit1:
	unregister_signal_handler();
exit0:
	return ret;
}

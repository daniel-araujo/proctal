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
	if (!register_signal_handler()) {
		fprintf(stderr, "Failed to set up signal handler.\n");
		return 1;
	}

	proctal_t p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	if (!arg->read && !arg->write && !arg->execute) {
		fprintf(stderr, "Did not specify what to watch for.\n");
		proctal_destroy(p);
		return 1;
	}

	if (!(arg->read && arg->write && !arg->execute)
		&& !(arg->write && !arg->read && !arg->execute)
		&& !(!arg->write && !arg->read && arg->execute)) {
		fprintf(stderr, "The given combination of read, write and execute options is not supported.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	proctal_watch_set_address(p, arg->address);
	proctal_watch_set_read(p, arg->read);
	proctal_watch_set_write(p, arg->write);
	proctal_watch_set_execute(p, arg->execute);

	// TODO: Should use a data structure with better lookup performance.
	struct darr matches;
	darr_init(&matches, sizeof(void *));
	darr_resize(&matches, 42);
	size_t match_count = 0;

	proctal_freeze(p);

	while (!request_quit) {
		void *addr;

		if (!proctal_watch(p, &addr)) {
			break;
		}

		if (arg->unique) {
			int match = 0;

			for (size_t i = 0; i < match_count; ++i) {
				void **prev = darr_address(&matches, i);

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

				void **e = darr_address(&matches, match_count - 1);
				*e = addr;
			}
		}

		cli_print_address(addr);
		printf("\n");
	}

	darr_deinit(&matches);

	unregister_signal_handler();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_unfreeze(p);

	proctal_destroy(p);

	return 0;
}

#include <signal.h>
#include <proctal.h>

#include "cmd.h"
#include "printer.h"

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

int proctal_cmd_watch(struct proctal_cmd_watch_arg *arg)
{
	if (!register_signal_handler()) {
		fprintf(stderr, "Failed to set up signal handler.\n");
		return 1;
	}

	proctal p = proctal_create();

	if (proctal_error(p)) {
		proctal_print_error(p);
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

	proctal_watch pw = proctal_watch_create(p);

	if (proctal_error(p)) {
		proctal_print_error(p);
		proctal_watch_destroy(pw);
		proctal_destroy(p);
		return 1;
	}

	proctal_watch_set_addr(pw, arg->address);
	proctal_watch_set_read(pw, arg->read);
	proctal_watch_set_write(pw, arg->write);
	proctal_watch_set_execute(pw, arg->execute);

	proctal_cmd_val_attr addr_attr = proctal_cmd_val_attr_create(PROCTAL_CMD_VAL_TYPE_ADDRESS);
	proctal_cmd_val addr = proctal_cmd_val_create(addr_attr);
	proctal_cmd_val_attr_destroy(addr_attr);

	while (!request_quit) {
 		if (!proctal_watch_next(pw, (void **) proctal_cmd_val_addr(addr))) {
 			break;
 		}

		proctal_cmd_val_print(addr, stdout);
		printf("\n");
	}

	unregister_signal_handler();

	proctal_cmd_val_destroy(addr);

	if (proctal_error(p)) {
		proctal_print_error(p);
		proctal_watch_destroy(pw);
		proctal_destroy(p);
		return 1;
	}

	proctal_watch_destroy(pw);

	if (proctal_error(p)) {
		proctal_print_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_destroy(p);

	return 0;
}

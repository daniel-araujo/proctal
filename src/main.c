#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "proctal.h"
#include "command.h"
#include "args.yucc"

int parse_lstr_int(const char *string, size_t length, int *i)
{
	// Temporary.
	errno = 0;
	*i = strtol(string, NULL, 10);

	if (errno != 0) {
		return -1;
	}

	return 0;
}

int parse_lstr_address(const char *string, size_t length, void **addr)
{
	// Temporary.
	errno = 0;
	*addr = (void *) strtol(string, NULL, 16);

	if (errno != 0) {
		return -1;
	}

	return 0;
}

int parse_zstr_int(const char *string, int *i)
{
	return parse_lstr_int(string, strlen(string), i);
}

int parse_zstr_address(const char *string, void *addr)
{
	return parse_lstr_address(string, strlen(string), addr);
}

int yuck_arg_to_proctal_command_read_arg(yuck_t *yuck_arg, struct proctal_command_read_arg *proctal_command_arg)
{
	if (yuck_arg->cmd != PROCTAL_CMD_READ) {
		fputs("Wrong command\n", stderr);
		return -1;
	}

	if (yuck_arg->nargs != 2) {
		fputs("Wrong number of arguments\n", stderr);
		return -1;
	}

	if (parse_zstr_int(yuck_arg->args[0], &proctal_command_arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		return -1;
	}

	if (parse_zstr_address(yuck_arg->args[1], &proctal_command_arg->address)) {
		fputs("Invalid address.\n", stderr);
		return -1;
	}

	return 0;
}

int yuck_arg_to_proctal_command_write_arg(yuck_t *yuck_arg, struct proctal_command_write_arg *proctal_command_arg)
{
	if (yuck_arg->cmd != PROCTAL_CMD_WRITE) {
		fputs("Wrong command\n", stderr);
		return -1;
	}

	if (yuck_arg->nargs != 3) {
		fputs("Wrong number of arguments\n", stderr);
		return -1;
	}

	if (parse_zstr_int(yuck_arg->args[0], &proctal_command_arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		return -1;
	}

	if (parse_zstr_address(yuck_arg->args[1], &proctal_command_arg->address)) {
		fputs("Invalid address.\n", stderr);
		return -1;
	}

	if (parse_zstr_int(yuck_arg->args[2], &proctal_command_arg->value)) {
		fputs("Invalid value.\n", stderr);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
 	yuck_t argp;

	if (yuck_parse(&argp, argc, argv) != 0) {
		// Yuck's error messages are fine for now. Just end it here.
		goto bad_parse;
	}

	if (argp.help_flag) {
		yuck_auto_help(&argp);
	} else if (argp.version_flag) {
		yuck_auto_version(&argp);
	} else if (argp.cmd == YUCK_NOCMD) {
		yuck_auto_usage(&argp);
		yuck_auto_help(&argp);
	} else if (argp.cmd == PROCTAL_CMD_WRITE) {
		struct proctal_command_write_arg arg;

		if (yuck_arg_to_proctal_command_write_arg(&argp, &arg) != 0) {
			goto bad_parse;
		}

		proctal_command_write(&arg);
	} else if (argp.cmd == PROCTAL_CMD_READ) {
		struct proctal_command_read_arg arg;

		if (yuck_arg_to_proctal_command_read_arg(&argp, &arg) != 0) {
			goto bad_parse;
		}

		proctal_command_read(&arg);
	}

	yuck_free(&argp);

	return 0;

bad_parse:
	yuck_free(&argp);

	return 1;
}

#include <stdio.h>

#include "proctal.h"
#include "args.yucc"

int main(int argc, char **argv)
{
 	yuck_t argp;

	if (yuck_parse(&argp, argc, argv) != 0) {
		return 1;
	}

	// These flags are special in that they disrupt the normal flow of
	// execution.
	if (argp.help_flag) {
		yuck_auto_help(&argp);
		goto exit;
	} else if (argp.version_flag) {
		yuck_auto_version(&argp);
		goto exit;
	}

	if (argp.cmd == YUCK_NOCMD) {
		yuck_auto_usage(&argp);
		yuck_auto_help(&argp);
	} else if (argp.cmd == PROCTAL_CMD_WRITE) {
	} else if (argp.cmd == PROCTAL_CMD_READ) {
	}

exit:
	yuck_free(&argp);

	return 0;
}

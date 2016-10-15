#include <stdio.h>

#include "proctal.h"
#include "cmdline.h"

int main(int argc, char **argv)
{
	struct gengetopt_args_info ai;

	if (cmdline_parser(argc, argv, &ai) != 0) {
		return 1;
	}

	return 0;
}

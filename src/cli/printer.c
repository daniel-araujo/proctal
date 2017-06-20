#include <stdio.h>
#include <inttypes.h>

#include "cli/printer.h"
#include "magic/magic.h"

static const char *proctal_error_messages[] = {
	[0] = NULL,
	[PROCTAL_ERROR_OUT_OF_MEMORY] = "Ran out of memory.",
	[PROCTAL_ERROR_PERMISSION_DENIED] = "Permission denied.",
	[PROCTAL_ERROR_WRITE_FAILURE] = "Failed to write everything out.",
	[PROCTAL_ERROR_READ_FAILURE] = "Failed to read everything in.",
	[PROCTAL_ERROR_UNKNOWN] = "An unknown failure occurred.",
	[PROCTAL_ERROR_UNIMPLEMENTED] = "Feature not implemented.",
	[PROCTAL_ERROR_UNSUPPORTED] = "Feature not supported.",
	[PROCTAL_ERROR_UNSUPPORTED_WATCH_READ] =
		"Watching only for reads is not supported yet."
		" You can watch for both reads and writes, though.",
	[PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_EXECUTE] =
		"Watching for reads and instruction executions at once is not supported.",
	[PROCTAL_ERROR_UNSUPPORTED_WATCH_WRITE_EXECUTE] =
		"Watching for writes and instruction executions at once is not supported.",
	[PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_WRITE_EXECUTE] =
		"Watching for reads, writes and instruction executions at once is not supported.",
	[PROCTAL_ERROR_PROCESS_NOT_FOUND] = "Process not found.",
	[PROCTAL_ERROR_PROCESS_NOT_SET] = "Process was not set.",
	[PROCTAL_ERROR_INJECT_ADDR_NOT_FOUND] = "Could not find a suitable address in memory to inject code in.",
	[PROCTAL_ERROR_PROCESS_SEGFAULT] = "Process hit segmentation fault.",
	[PROCTAL_ERROR_PROCESS_EXITED] = "Process has exited.",
	[PROCTAL_ERROR_PROCESS_STOPPED] = "Process has stopped.",
	[PROCTAL_ERROR_PROCESS_UNTAMEABLE] = "Process is in a state that cannot be dealt with.",
};

static const char *cli_pattern_error_messages[] = {
	[0] = "Unknown error with pattern.",
	[CLI_PATTERN_ERROR_INVALID_PATTERN] = "Invalid pattern found at offset %d.",
	[CLI_PATTERN_ERROR_OUT_OF_MEMORY] = "Ran out of memory.",
	[CLI_PATTERN_ERROR_EMPTY_PATTERN] = "Pattern cannot match anything because it's empty.",
	[CLI_PATTERN_ERROR_MISSING_WHITESPACE] = "Missing whitespace at offset %d.",
	[CLI_PATTERN_ERROR_COMPILE_PATTERN] = "You must compile a pattern beforehand.",
};

void cli_print_proctal_error(proctal_t p)
{
	int error = proctal_error(p);

	if (error == 0) {
		return;
	}

	if (!((unsigned) error < ARRAY_SIZE(proctal_error_messages))) {
		error = PROCTAL_ERROR_UNKNOWN;
	}

	fprintf(stderr, "%s\n", proctal_error_messages[error]);
}

void cli_print_pattern_error(cli_pattern cp)
{
	int error = cli_pattern_error(cp);

	if (error == 0) {
		return;
	}

	if (!((unsigned) error < ARRAY_SIZE(cli_pattern_error_messages))) {
		error = 0;
	}

	switch (error) {
	case CLI_PATTERN_ERROR_INVALID_PATTERN:
	case CLI_PATTERN_ERROR_MISSING_WHITESPACE:
		fprintf(stderr, cli_pattern_error_messages[error], cli_pattern_error_compile_offset(cp));
		fprintf(stderr, "\n");
		break;

	default:
		fprintf(stderr, "%s\n", cli_pattern_error_messages[error]);
		break;
	}
}

void cli_print_address(void *address)
{
	uintptr_t a = (uintptr_t) address;

	printf("%" PRIXPTR, a);
}

void cli_print_byte(unsigned char byte)
{
	printf("%02hhx", byte);
}

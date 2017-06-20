#include <stdio.h>
#include <stdlib.h>
#include <keystone/keystone.h>

#include "cli/cmd/execute.h"
#include "cli/printer.h"
#include "lib/include/proctal.h"

static void free_read(char **buf)
{
	if (*buf == NULL) {
		return;
	}

	free(*buf);
	*buf = NULL;
}

static size_t read(char **buf)
{
	const size_t CHUNK_SIZE = 128;
	FILE *in = stdin;
	size_t size = 0;

	*buf = NULL;

	do {
		char *mem = realloc(*buf, size + CHUNK_SIZE + 1);

		if (mem == NULL) {
			fprintf(stderr, "Failed to allocate enough memory.\n");
			free_read(buf);
			return 0;
		}

		*buf = mem;

		size += fread(*buf + size, 1, CHUNK_SIZE, in);
	} while (!feof(in));

	if (size == 0) {
		free_read(buf);
		return 0;
	}

	// Although we're returning the size, we're going to need to do some
	// operations that require the string to be terminated by NUL.
	// The size will not include the NUL character.
	(*buf)[size] = '\0';

	return size;
}

static void free_assemble(char **buf)
{
	ks_free((unsigned char *) *buf);
	*buf = NULL;
}

static size_t assemble(char **buf, char *assembly)
{
	ks_engine *ks;

	size_t count;
	size_t size;

	if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) {
		return 0;
	}

	if (ks_asm(ks, assembly, 0, (unsigned char **) buf, &size, &count) != KS_ERR_OK) {
		fprintf(stderr, "Failed to assemble code: %s\n", ks_strerror(ks_errno(ks)));
		ks_close(ks);
		return 0;
	}

	ks_close(ks);

	return size;
}

int cli_cmd_execute(struct cli_cmd_execute_arg *arg)
{
	proctal_t p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	char *input;
	size_t input_size = read(&input);

	if (input_size == 0) {
		proctal_destroy(p);
		return 1;
	}

	switch (arg->format) {
	case CLI_CMD_EXECUTE_FORMAT_ASSEMBLY: {
		char *compiled;
		size_t compiled_size = assemble(&compiled, input);

		if (compiled_size == 0) {
			proctal_destroy(p);
			return 1;
		}

		proctal_execute(p, compiled, compiled_size);
		free_assemble(&compiled);
		break;
	}

	case CLI_CMD_EXECUTE_FORMAT_BYTECODE:
		proctal_execute(p, input, input_size);
		break;

	default:
		fprintf(stderr, "Not implemented.\n");
		free_read(&input);
		proctal_destroy(p);
		return 1;
	}

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		free_read(&input);
		proctal_destroy(p);
		return 1;
	}

	free_read(&input);
	proctal_destroy(p);

	return 0;
}

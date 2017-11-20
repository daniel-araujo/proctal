#include <stdio.h>
#include <stdlib.h>
#include <darr.h>

#include "cli/cmd/execute.h"
#include "cli/printer.h"
#include "cli/parser.h"
#include "cli/assembler.h"
#include "api/include/proctal.h"

static int read(struct darr *buffer)
{
	const float GROWTH_FACTOR = 1.5;
	const size_t CHUNK_SIZE = 1024;
	FILE *in = stdin;
	size_t size = darr_size(buffer);

	if (!darr_grow(buffer, 1024)) {
		fprintf(stderr, "Failed to allocate memory to store input.\n");
		return 0;
	}

	do {
		if ((size + CHUNK_SIZE) >= darr_size(buffer)) {
			if (!darr_grow(buffer, darr_size(buffer) * GROWTH_FACTOR)) {
				fprintf(stderr, "Failed to allocate memory to store input.\n");
				return 0;
			}
		}

		char *data = darr_data(buffer);

		size += fread(data + size, 1, CHUNK_SIZE, in);
	} while (!feof(in));

	darr_resize(buffer, size);
	return 1;
}

static int assemble(struct cli_assembler *assembler, struct darr *assembly, struct darr *bytecode)
{
	const float GROWTH_FACTOR = 1.5;
	size_t bytecode_position = 0;
	size_t assembly_position = 0;
	int assembly_line = 1;
	char *assembly_ch = darr_element(assembly, 0);

	if (!darr_grow(bytecode, 1024)) {
		fprintf(stderr, "Failed to allocate memory to store bytecode.\n");
		return 0;
	}

	for (;;) {
		// Skip spaces.
		assembly_position += cli_parse_skip_chars2(
			darr_element(assembly, assembly_position),
			darr_size(assembly) - assembly_position,
			" \t");

		if (assembly_position == darr_size(assembly)) {
			// No more characters to read.
			break;
		}

		if (assembly_ch[assembly_position] == ';') {
			// This line is a comment. Skip it.
			assembly_position += cli_parse_skip_until_chars2(
				darr_element(assembly, assembly_position),
				darr_size(assembly) - assembly_position,
				"\n");
			++assembly_line;
			continue;
		}

		if (assembly_ch[assembly_position] == '\n') {
			// This line is empty.
			++assembly_position;
			++assembly_line;
			continue;
		}

		// How many characters the next assembly statement takes up.
		size_t statement_size = cli_parse_skip_until_chars2(
			darr_element(assembly, assembly_position),
			darr_size(assembly) - assembly_position,
			";\n");

		// When we get here we always expect a statement.
		assert(statement_size != 0);

		struct cli_assembler_compile_result result;
		int success = cli_assembler_compile(
			assembler,
			darr_element(assembly, assembly_position),
			statement_size,
			&result);
		if (!success) {
			fprintf(
				stderr,
				"Failed to parse line %d: %s\n",
				assembly_line,
				cli_assembler_error_message(assembler));
			return 0;
		}

		assembly_position += result.read;

		if ((bytecode_position + result.bytecode_size) >= darr_size(bytecode)) {
			if (!darr_grow(bytecode, darr_size(bytecode) * GROWTH_FACTOR)) {
				fprintf(stderr, "Failed to allocate memory to store bytecode.\n");
				cli_assembler_compile_dispose(&result);
				return 0;
			}
		}

		memcpy(
			darr_element(bytecode, bytecode_position),
			result.bytecode,
			result.bytecode_size);

		bytecode_position += result.bytecode_size;

		cli_assembler_compile_dispose(&result);

		// Get to the next line.
		assembly_position += cli_parse_skip_until_chars2(
			darr_element(assembly, assembly_position),
			darr_size(assembly) - assembly_position,
			"\n");

		if (assembly_position == darr_size(assembly)) {
			// No more characters to read.
			break;
		}

		++assembly_position;
		++assembly_line;
	}

	// Deallocate extra space.
	darr_resize(bytecode, bytecode_position);

	return 1;
}

int cli_cmd_execute(struct cli_cmd_execute_arg *arg)
{
	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_close(p);
		return 1;
	}

	proctal_pid_set(p, arg->pid);

	struct darr input;
	darr_init(&input, sizeof(char));

	if (!read(&input) || darr_empty(&input)) {
		darr_deinit(&input);
		proctal_close(p);
		return 1;
	}

	switch (arg->format) {
	case CLI_CMD_EXECUTE_FORMAT_ASSEMBLY: {
		struct cli_assembler assembler;
		cli_assembler_init(&assembler);
		cli_assembler_architecture_set(&assembler, arg->assembly_architecture);
		cli_assembler_mode_set(&assembler, arg->assembly_mode);
		cli_assembler_syntax_set(&assembler, arg->assembly_syntax);

		struct darr bytecode;
		darr_init(&bytecode, sizeof(char));

		if (!assemble(&assembler, &input, &bytecode)) {
			darr_deinit(&input);
			darr_deinit(&bytecode);
			cli_assembler_deinit(&assembler);
			proctal_close(p);
			return 1;
		}

		proctal_execute(p, darr_data(&bytecode), darr_size(&bytecode));

		darr_deinit(&bytecode);
		cli_assembler_deinit(&assembler);
		break;
	}

	case CLI_CMD_EXECUTE_FORMAT_BYTECODE:
		proctal_execute(p, darr_data(&input), darr_size(&input));
		break;

	default:
		fprintf(stderr, "Not implemented.\n");
		darr_deinit(&input);
		proctal_close(p);
		return 1;
	}

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		darr_deinit(&input);
		proctal_close(p);
		return 1;
	}

	darr_deinit(&input);
	proctal_close(p);

	return 0;
}

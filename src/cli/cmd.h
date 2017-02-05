#ifndef CLI_CMD_H
#define CLI_CMD_H

#include "cli/val.h"
#include "cli/val-list.h"

enum cli_cmd_execute_format {
	CLI_CMD_EXECUTE_FORMAT_ASSEMBLY,
	CLI_CMD_EXECUTE_FORMAT_BYTECODE,
};

struct cli_cmd_read_arg {
	int pid;

	void *address;

	// Number of values expected to read.
	size_t array;

	// How we're going to interpret values.
	cli_val value;

	// Whether to additionally print the value's address. Useful when
	// printing a lot of adjacent values of variable length.
	int show_address;

	// Whether to additionally print the byte code of the instruction.
	int show_instruction_byte_code;
};

struct cli_cmd_write_arg {
	int pid;

	void *address;

	// Number of values expected to write.
	size_t array;

	// List of values to write.
	cli_val_list value_list;

	// Whether to write the same value repeatedly until the program is told
	// to shut down.
	int repeat;
	// A delay in milliseconds before writing to the address again. Without
	// a delay you could theoretically turn your CPU into a heater.
	int repeat_delay;
};

struct cli_cmd_search_arg {
	int pid;

	// How we're going to interpret values.
	cli_val value;

	// Whether to search readable memory addresses.
	int read;

	// Whether to search writable memory addresses.
	int write;

	// Whether to search executable memory addresses.
	int execute;

	// Whether we're going to read from stdin.
	int input;

	// Whether to perform an equality check.
	int eq;
	cli_val eq_value;

	// Whether to perform a not equals check.
	int ne;
	cli_val ne_value;

	// Whether to perform greather than.
	int gt;
	cli_val gt_value;

	// Whether to perform greather than equals.
	int gte;
	cli_val gte_value;

	// Whether to perform less than.
	int lt;
	cli_val lt_value;

	// Whether to perform less than equals.
	int lte;
	cli_val lte_value;

	// Whether to check if it was incremented.
	int inc;
	cli_val inc_value;

	// Whether to check if it was incremented up to and including value.
	int inc_up_to;
	cli_val inc_up_to_value;

	// Whether to check if it was decremented.
	int dec;
	cli_val dec_value;

	// Whether to check if it was decremented up to and including value.
	int dec_up_to;
	cli_val dec_up_to_value;

	// Whether to check if it was changed.
	int changed;

	// Whether to check if it was unchanged.
	int unchanged;

	// Whether to check if it was increased.
	int increased;

	// Whether to check if it was decreased.
	int decreased;
};

struct cli_cmd_pattern_arg {
	int pid;

	const char *pattern;

	// Whether to quit when no more input is available.
	int input;

	// Whether to search readable memory addresses.
	int read;

	// Whether to search writable memory addresses.
	int write;

	// Whether to search executable memory addresses.
	int execute;

	// Whether to search program code.
	int program_code;
};

struct cli_cmd_freeze_arg {
	int pid;

	// Whether to quit when no more input is available.
	int input;
};

struct cli_cmd_watch_arg {
	int pid;

	void *address;

	// Whether to watch for reads.
	int read;

	// Whether to watch for writes.
	int write;

	// Whether to watch for instruction execution.
	int execute;

	// Whether to print an address only once.
	int unique;
};

struct cli_cmd_execute_arg {
	int pid;

	// What format we're expecting the input to be.
	enum cli_cmd_execute_format format;
};

struct cli_cmd_alloc_arg {
	int pid;

	// Requested size.
	size_t size;

	// Read permission.
	int read;

	// Write permission.
	int write;

	// Execute permission.
	int execute;
};

struct cli_cmd_dealloc_arg {
	int pid;

	void *address;
};

struct cli_cmd_measure_arg {
	void *address;

	// Number of values that would be expected to write.
	size_t array;

	cli_val_list value_list;
};

struct cli_cmd_dump_arg {
	int pid;

	// Whether to dump readable memory addresses.
	int read;

	// Whether to dump writable memory addresses.
	int write;

	// Whether to dump executable memory addresses.
	int execute;

	// Whether to dump program code.
	int program_code;
};

int cli_cmd_read(struct cli_cmd_read_arg *arg);

int cli_cmd_write(struct cli_cmd_write_arg *arg);

int cli_cmd_search(struct cli_cmd_search_arg *arg);

int cli_cmd_pattern(struct cli_cmd_pattern_arg *arg);

int cli_cmd_freeze(struct cli_cmd_freeze_arg *arg);

int cli_cmd_watch(struct cli_cmd_watch_arg *arg);

int cli_cmd_execute(struct cli_cmd_execute_arg *arg);

int cli_cmd_alloc(struct cli_cmd_alloc_arg *arg);

int cli_cmd_dealloc(struct cli_cmd_dealloc_arg *arg);

int cli_cmd_measure(struct cli_cmd_measure_arg *arg);

int cli_cmd_dump(struct cli_cmd_dump_arg *arg);

#endif /* CLI_CMD_H */

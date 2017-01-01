#include <stdio.h>
#include <stdlib.h>
#include <proctal.h>

#include "cmd.h"
#include "parser.h"
#include "args.yucc"

/*
 * This macro is used to fill up a struct type_arguments based on the arguments
 * given to a yuck argument structure.
 *
 * The macro expects both to be passed by value.
 */
#define TYPE_ARGUMENTS_FROM_YUCK_ARG(STRUCT, YUCK) \
	STRUCT.type = cli_val_type_by_name(YUCK.type_arg); \
\
	switch (STRUCT.type) { \
	case CLI_VAL_TYPE_INTEGER: \
		STRUCT.integer_endianness = cli_val_integer_endianness_by_name(YUCK.integer_endianness_arg); \
		STRUCT.integer_size = cli_val_integer_size_by_name(YUCK.integer_size_arg); \
		STRUCT.integer_sign = cli_val_integer_sign_by_name(YUCK.integer_sign_arg); \
		break; \
\
	case CLI_VAL_TYPE_IEEE754: \
		STRUCT.ieee754_precision = cli_val_ieee754_precision_by_name(YUCK.ieee754_precision_arg); \
		break; \
\
	case CLI_VAL_TYPE_TEXT: \
		STRUCT.text_charset = cli_val_text_charset_by_name(YUCK.text_charset_arg); \
		break; \
\
	case CLI_VAL_TYPE_INSTRUCTION: \
		STRUCT.instruction_arch = cli_val_instruction_arch_by_name(YUCK.instruction_arch_arg); \
		break; \
	}

/*
 * Structure used for parsing options by name.
 */
struct value_options {
	const char *name;
	void* value;
};

/*
 * This structure contains all type options parsed.
 */
struct type_arguments {
	enum cli_val_type type;
	enum cli_val_integer_endianness integer_endianness;
	enum cli_val_integer_sign integer_sign;
	enum cli_val_integer_size integer_size;
	enum cli_val_ieee754_precision ieee754_precision;
	enum cli_val_text_charset text_charset;
	enum cli_val_instruction_arch instruction_arch;
};

/*
 * Creates a cli_val from a struct type_arguments. You only have to have
 * initialized the data members that are relevant to the type.
 *
 * You are expected to keep track of the life time of the returned cli_val.
 *
 * Returns a nil value on failure.
 */
static cli_val create_cli_val_from_type_arguments(struct type_arguments *ta)
{
	switch (ta->type) {
	case CLI_VAL_TYPE_INTEGER: {
		struct cli_val_integer_attr a;
		cli_val_integer_attr_init(&a);
		cli_val_integer_attr_set_size(&a, ta->integer_size);
		cli_val_integer_attr_set_sign(&a, ta->integer_sign);
		cli_val_integer_attr_set_endianness(&a, ta->integer_endianness);

		struct cli_val_integer *v = cli_val_integer_create(&a);

		cli_val_integer_attr_deinit(&a);

		if (v == NULL) {
			break;
		}

		return cli_val_wrap(ta->type, v);
	}

	case CLI_VAL_TYPE_IEEE754: {
		struct cli_val_ieee754_attr a;
		cli_val_ieee754_attr_init(&a);
		cli_val_ieee754_attr_set_precision(&a, ta->ieee754_precision);

		struct cli_val_ieee754 *v = cli_val_ieee754_create(&a);

		cli_val_ieee754_attr_deinit(&a);

		if (v == NULL) {
			break;
		}

		return cli_val_wrap(ta->type, v);
	}

	case CLI_VAL_TYPE_TEXT: {
		struct cli_val_text_attr a;
		cli_val_text_attr_init(&a);
		cli_val_text_attr_set_charset(&a, ta->text_charset);

		struct cli_val_text *v = cli_val_text_create(&a);

		cli_val_text_attr_deinit(&a);

		if (v == NULL) {
			break;
		}

		return cli_val_wrap(ta->type, v);
	}

	case CLI_VAL_TYPE_BYTE: {
		struct cli_val_byte *v = cli_val_byte_create();

		if (v == NULL) {
			break;
		}

		return cli_val_wrap(ta->type, v);
	}

	case CLI_VAL_TYPE_INSTRUCTION: {
		struct cli_val_instruction_attr a;
		cli_val_instruction_attr_init(&a);
		cli_val_instruction_attr_set_arch(&a, ta->instruction_arch);

		struct cli_val_instruction *v = cli_val_instruction_create(&a);

		cli_val_instruction_attr_deinit(&a);

		if (v == NULL) {
			break;
		}

		return cli_val_wrap(ta->type, v);
	}

	case CLI_VAL_TYPE_ADDRESS: {
		struct cli_val_address *v = cli_val_address_create();

		if (v == NULL) {
			break;
		}

		return cli_val_wrap(ta->type, v);
	}
	}

	return cli_val_nil();
}

/*
 * Returns the value whose name in options is equal to the given name,
 * otherwise returns fallback.
 */
static void *value_by_name(struct value_options *options, size_t length, const char *name, void *fallback)
{
	if (name == NULL) {
		return fallback;
	}

	for (size_t i = 0; i < length; i++) {
		if (strcmp(options[i].name, name) == 0) {
			return options[i].value;
		}
	}

	return fallback;
}

static enum cli_val_type cli_val_type_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "byte",
			.value = (void *) CLI_VAL_TYPE_BYTE,
		},
		{
			.name = "integer",
			.value = (void *) CLI_VAL_TYPE_INTEGER,
		},
		{
			.name = "ieee754",
			.value = (void *) CLI_VAL_TYPE_IEEE754,
		},
		{
			.name = "text",
			.value = (void *) CLI_VAL_TYPE_TEXT,
		},
		{
			.name = "address",
			.value = (void *) CLI_VAL_TYPE_ADDRESS,
		},
		{
			.name = "instruction",
			.value = (void *) CLI_VAL_TYPE_INSTRUCTION,
		},
	};

	return (enum cli_val_type) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) CLI_VAL_TYPE_BYTE);
}

static enum cli_val_integer_endianness cli_val_integer_endianness_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "little",
			.value = (void *) CLI_VAL_INTEGER_ENDIANNESS_LITTLE,
		},
	};

	return (enum cli_val_integer_endianness) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) CLI_VAL_INTEGER_ENDIANNESS_LITTLE);
}

static enum cli_val_integer_size cli_val_integer_size_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "8",
			.value = (void *) CLI_VAL_INTEGER_SIZE_8,
		},
		{
			.name = "16",
			.value = (void *) CLI_VAL_INTEGER_SIZE_16,
		},
		{
			.name = "32",
			.value = (void *) CLI_VAL_INTEGER_SIZE_32,
		},
		{
			.name = "64",
			.value = (void *) CLI_VAL_INTEGER_SIZE_64,
		},
	};

	return (enum cli_val_integer_size) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) CLI_VAL_INTEGER_SIZE_8);
}

static enum cli_val_integer_sign cli_val_integer_sign_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "unsigned",
			.value = (void *) CLI_VAL_INTEGER_SIGN_UNSIGNED,
		},
		{
			.name = "2scmpl",
			.value = (void *) CLI_VAL_INTEGER_SIGN_2SCMPL,
		},
	};

	return (enum cli_val_integer_sign) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) CLI_VAL_INTEGER_SIGN_2SCMPL);
}

static enum cli_val_ieee754_precision cli_val_ieee754_precision_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "single",
			.value = (void *) CLI_VAL_IEEE754_PRECISION_SINGLE,
		},
		{
			.name = "double",
			.value = (void *) CLI_VAL_IEEE754_PRECISION_DOUBLE,
		},
		{
			.name = "extended",
			.value = (void *) CLI_VAL_IEEE754_PRECISION_EXTENDED,
		},
	};

	return (enum cli_val_ieee754_precision) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) CLI_VAL_IEEE754_PRECISION_SINGLE);
}

static enum cli_val_text_charset cli_val_text_charset_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "ascii",
			.value = (void *) CLI_VAL_TEXT_CHARSET_ASCII,
		},
	};

	return (enum cli_val_text_charset) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) CLI_VAL_TEXT_CHARSET_ASCII);
}

static enum cli_val_instruction_arch cli_val_instruction_arch_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "x86-64",
			.value = (void *) CLI_VAL_INSTRUCTION_ARCH_X86_64,
		},
	};

	return (enum cli_val_instruction_arch) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) CLI_VAL_INSTRUCTION_ARCH_X86_64);
}

static enum cli_cmd_execute_format cli_cmd_execute_format_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "assembly",
			.value = (void *) CLI_CMD_EXECUTE_FORMAT_ASSEMBLY,
		},
		{
			.name = "bytecode",
			.value = (void *) CLI_CMD_EXECUTE_FORMAT_BYTECODE,
		},
	};

	return (enum cli_cmd_execute_format) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) CLI_CMD_EXECUTE_FORMAT_ASSEMBLY);
}

static void destroy_cli_cmd_read_arg_from_yuck_arg(struct cli_cmd_read_arg *arg)
{
	if (arg->value != cli_val_nil()) {
		cli_val_destroy(arg->value);
	}

	free(arg);
}

static struct cli_cmd_read_arg *create_cli_cmd_read_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_read_arg *arg = malloc(sizeof *arg);
	arg->value = cli_val_nil();

	if (yuck_arg->cmd != PROCTAL_CMD_READ) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Wrong number of arguments.\n", stderr);
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->read.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->read.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.array_arg != NULL) {
		unsigned long v;

		if (!cli_parse_ulong(yuck_arg->read.array_arg, &v)) {
			fputs("Invalid array size.\n", stderr);
			destroy_cli_cmd_read_arg_from_yuck_arg(arg);
			return NULL;
		}

		arg->array = v;
	} else {
		arg->array = 1;
	}

	struct type_arguments type_args;
	TYPE_ARGUMENTS_FROM_YUCK_ARG(type_args, yuck_arg->read)

	arg->value = create_cli_val_from_type_arguments(&type_args);

	if (arg->value == cli_val_nil()) {
		fputs("Invalid type arguments.\n", stderr);
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->show_instruction_address = yuck_arg->read.show_instruction_address_flag == 1;
	arg->show_instruction_byte_code = yuck_arg->read.show_instruction_byte_code_flag == 1;

	return arg;
}

static void destroy_cli_cmd_write_arg_from_yuck_arg(struct cli_cmd_write_arg *arg)
{
	cli_val_list_destroy(arg->value_list);
	free(arg);
}

static struct cli_cmd_write_arg *create_cli_cmd_write_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_write_arg *arg = malloc(sizeof *arg);
	arg->value_list = cli_val_list_create(yuck_arg->nargs);

	if (yuck_arg->cmd != PROCTAL_CMD_WRITE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs == 0) {
		fputs("You must provide at least 1 value.\n", stderr);
		destroy_cli_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->write.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->write.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->write.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_cli_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->write.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	struct type_arguments type_args;
	TYPE_ARGUMENTS_FROM_YUCK_ARG(type_args, yuck_arg->write)

	for (size_t i = 0; i < yuck_arg->nargs; ++i) {
		cli_val v = create_cli_val_from_type_arguments(&type_args);

		if (v == cli_val_nil()) {
			fputs("Invalid type arguments.\n", stderr);
			destroy_cli_cmd_write_arg_from_yuck_arg(arg);
			return NULL;
		}

		if (!cli_val_parse(v, yuck_arg->args[i])) {
			fprintf(stderr, "Value #%zu is invalid.\n", i + 1);
			cli_val_destroy(v);
			destroy_cli_cmd_write_arg_from_yuck_arg(arg);
			return NULL;
		}

		cli_val_list_set(arg->value_list, i, v);
	}

	if (yuck_arg->write.array_arg != NULL) {
		unsigned long v;

		if (!cli_parse_ulong(yuck_arg->read.array_arg, &v)) {
			fputs("Invalid array size.\n", stderr);
			destroy_cli_cmd_write_arg_from_yuck_arg(arg);
			return NULL;
		}

		arg->array = v;
	} else {
		arg->array = cli_val_list_size(arg->value_list);
	}

	if (yuck_arg->write.repeat_flag) {
		arg->repeat = 1;

		if (yuck_arg->write.repeat_delay_arg) {
			if (!cli_parse_int(yuck_arg->write.repeat_delay_arg, &arg->repeat_delay)) {
				fputs("Invalid repeat delay.\n", stderr);
				destroy_cli_cmd_write_arg_from_yuck_arg(arg);
				return NULL;
			}
		} else {
			arg->repeat_delay = 5;
		}
	} else {
		arg->repeat = 0;
	}


	return arg;
}

static void destroy_cli_cmd_search_arg_from_yuck_arg(struct cli_cmd_search_arg *arg)
{
	if (arg->value != cli_val_nil()) {
		cli_val_destroy(arg->value);
	}

#define DESTROY_COMPARE_ARG(PROCTALNAME) \
	if (arg->PROCTALNAME) { \
		cli_val_destroy(arg->PROCTALNAME##_value); \
	}

	DESTROY_COMPARE_ARG(eq);
	DESTROY_COMPARE_ARG(ne);
	DESTROY_COMPARE_ARG(gt);
	DESTROY_COMPARE_ARG(gte);
	DESTROY_COMPARE_ARG(lt);
	DESTROY_COMPARE_ARG(lte);
	DESTROY_COMPARE_ARG(inc);
	DESTROY_COMPARE_ARG(inc_up_to);
	DESTROY_COMPARE_ARG(dec);
	DESTROY_COMPARE_ARG(dec_up_to);

#undef DESTROY_COMPARE_ARG

	free(arg);
}

static struct cli_cmd_search_arg *create_cli_cmd_search_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_search_arg *arg = malloc(sizeof *arg);
	arg->value = cli_val_nil();
	arg->eq = 0;
	arg->ne = 0;
	arg->gt = 0;
	arg->gte = 0;
	arg->lt = 0;
	arg->lte = 0;
	arg->inc = 0;
	arg->inc_up_to = 0;
	arg->dec = 0;
	arg->dec_up_to = 0;
	arg->input = 0;

	arg->read = yuck_arg->search.read_flag == 1;
	arg->write = yuck_arg->search.write_flag == 1;
	arg->execute = yuck_arg->search.execute_flag == 1;

	if (yuck_arg->cmd != PROCTAL_CMD_SEARCH) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->search.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->search.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	enum cli_val_type t = cli_val_type_by_name(yuck_arg->search.type_arg);

	if (t == CLI_VAL_TYPE_INSTRUCTION) {
		fprintf(stderr, "Searching for assembly code is not supported.\n");
		destroy_cli_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	struct type_arguments type_args;
	TYPE_ARGUMENTS_FROM_YUCK_ARG(type_args, yuck_arg->search)

	arg->value = create_cli_val_from_type_arguments(&type_args);

	if (arg->value == cli_val_nil()) {
		fputs("Invalid type arguments.\n", stderr);
		destroy_cli_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->search.input_flag) {
		arg->input = 1;
	}

#define FORCE_POSITIVE(NAME) \
	if (yuck_arg->search.NAME##_arg != NULL \
		&& (strcmp("0", yuck_arg->search.NAME##_arg) == 0 \
			|| strncmp("-", yuck_arg->search.NAME##_arg, 1) == 0)) { \
		fputs("Value must be positive for --"#NAME".\n", stderr); \
		destroy_cli_cmd_search_arg_from_yuck_arg(arg); \
		return NULL; \
	}

	FORCE_POSITIVE(inc);
	FORCE_POSITIVE(inc_up_to);
	FORCE_POSITIVE(dec);
	FORCE_POSITIVE(dec_up_to);

#define GET_COMPARE_ARG(NAME) \
	if (yuck_arg->search.NAME##_arg != NULL) { \
		arg->NAME = 1; \
		arg->NAME##_value = create_cli_val_from_type_arguments(&type_args); \
		if (!cli_val_parse(arg->NAME##_value, yuck_arg->search.NAME##_arg)) { \
			fputs("Invalid value for --"#NAME".\n", stderr); \
			destroy_cli_cmd_search_arg_from_yuck_arg(arg); \
			return NULL; \
		} \
	} else { \
		arg->NAME = 0; \
	}

	GET_COMPARE_ARG(eq);
	GET_COMPARE_ARG(ne);
	GET_COMPARE_ARG(gt);
	GET_COMPARE_ARG(gte);
	GET_COMPARE_ARG(lt);
	GET_COMPARE_ARG(lte);
	GET_COMPARE_ARG(inc);
	GET_COMPARE_ARG(inc_up_to);
	GET_COMPARE_ARG(dec);
	GET_COMPARE_ARG(dec_up_to);

#undef GET_COMPARE_ARG

#define GET_OPTION_ARG(NAME) \
	if (yuck_arg->search.NAME##_flag) { \
		arg->NAME = 1; \
	} else { \
		arg->NAME = 0; \
	}

	GET_OPTION_ARG(changed);
	GET_OPTION_ARG(unchanged);
	GET_OPTION_ARG(increased);
	GET_OPTION_ARG(decreased);

#undef GET_OPTION_ARG

	return arg;
}

static void destroy_cli_cmd_pattern_arg_from_yuck_arg(struct cli_cmd_pattern_arg *arg)
{
	free(arg);
}

static struct cli_cmd_pattern_arg *create_cli_cmd_pattern_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_pattern_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_PATTERN) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_pattern_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 1) {
		fputs("Incorrect number of arguments.\n", stderr);
		destroy_cli_cmd_pattern_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->pattern.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_pattern_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->pattern.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_pattern_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->pattern = yuck_arg->args[0];

	arg->read = yuck_arg->pattern.read_flag == 1;
	arg->write = yuck_arg->pattern.write_flag == 1;
	arg->execute = yuck_arg->pattern.execute_flag == 1;
	arg->program_code = yuck_arg->pattern.program_code_flag == 1;

	return arg;
}

static void destroy_cli_cmd_freeze_arg_from_yuck_arg(struct cli_cmd_freeze_arg *arg)
{
	free(arg);
}

static struct cli_cmd_freeze_arg *create_cli_cmd_freeze_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_freeze_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_FREEZE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_freeze_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Too many arguments.\n", stderr);
		destroy_cli_cmd_freeze_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->freeze.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_freeze_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->freeze.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_freeze_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->input = yuck_arg->freeze.input_flag == 1;

	return arg;
}

static void destroy_cli_cmd_watch_arg_from_yuck_arg(struct cli_cmd_watch_arg *arg)
{
	free(arg);
}

static struct cli_cmd_watch_arg *create_cli_cmd_watch_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_watch_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_WATCH) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_watch_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Too many arguments.\n", stderr);
		destroy_cli_cmd_watch_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->watch.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_watch_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->watch.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_watch_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->watch.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_cli_cmd_watch_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->watch.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_watch_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->read = yuck_arg->watch.read_flag == 1;
	arg->write = yuck_arg->watch.write_flag == 1;
	arg->execute = yuck_arg->watch.execute_flag == 1;
	arg->unique = yuck_arg->watch.unique_flag == 1;

	return arg;
}

static void destroy_cli_cmd_execute_arg_from_yuck_arg(struct cli_cmd_execute_arg *arg)
{
	free(arg);
}

static struct cli_cmd_execute_arg *create_cli_cmd_execute_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_execute_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_EXECUTE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_execute_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Too many arguments.\n", stderr);
		destroy_cli_cmd_execute_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->execute.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_execute_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->execute.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_execute_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->format = cli_cmd_execute_format_by_name(yuck_arg->execute.format_arg);

	return arg;
}

static void destroy_cli_cmd_alloc_arg_from_yuck_arg(struct cli_cmd_alloc_arg *arg)
{
	free(arg);
}

static struct cli_cmd_alloc_arg *create_cli_cmd_alloc_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_alloc_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_ALLOC) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_alloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 1) {
		fputs("Incorrect number of arguments.\n", stderr);
		destroy_cli_cmd_alloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_ulong(yuck_arg->args[0], &arg->size)) {
		fputs("Invalid size.\n", stderr);
		destroy_cli_cmd_alloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->alloc.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_alloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->alloc.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_alloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->read = yuck_arg->alloc.read_flag == 1;
	arg->write = yuck_arg->alloc.write_flag == 1;
	arg->execute = yuck_arg->alloc.execute_flag == 1;

	return arg;
}

static void destroy_cli_cmd_dealloc_arg_from_yuck_arg(struct cli_cmd_dealloc_arg *arg)
{
	free(arg);
}

static struct cli_cmd_dealloc_arg *create_cli_cmd_dealloc_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_dealloc_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_DEALLOC) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_dealloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 1) {
		fputs("Incorrect number of arguments.\n", stderr);
		destroy_cli_cmd_dealloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->args[0], &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_dealloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->dealloc.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_dealloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->dealloc.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_dealloc_arg_from_yuck_arg(arg);
		return NULL;
	}

	return arg;
}

static void destroy_cli_cmd_measure_arg_from_yuck_arg(struct cli_cmd_measure_arg *arg)
{
	cli_val_list_destroy(arg->value_list);
	free(arg);
}

static struct cli_cmd_measure_arg *create_cli_cmd_measure_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_measure_arg *arg = malloc(sizeof *arg);
	arg->value_list = cli_val_list_create(yuck_arg->nargs);

	if (yuck_arg->cmd != PROCTAL_CMD_MEASURE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_measure_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs == 0) {
		fputs("You must provide at least 1 value.\n", stderr);
		destroy_cli_cmd_measure_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->measure.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_cli_cmd_measure_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->measure.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_measure_arg_from_yuck_arg(arg);
		return NULL;
	}

	struct type_arguments type_args;
	TYPE_ARGUMENTS_FROM_YUCK_ARG(type_args, yuck_arg->measure)

	for (size_t i = 0; i < yuck_arg->nargs; ++i) {
		cli_val v = create_cli_val_from_type_arguments(&type_args);

		if (v == cli_val_nil()) {
			fputs("Invalid type arguments.\n", stderr);
			destroy_cli_cmd_measure_arg_from_yuck_arg(arg);
			return NULL;
		}

		if (!cli_val_parse(v, yuck_arg->args[i])) {
			fprintf(stderr, "Value #%zu is invalid.\n", i + 1);
			cli_val_destroy(v);
			destroy_cli_cmd_measure_arg_from_yuck_arg(arg);
			return NULL;
		}

		cli_val_list_set(arg->value_list, i, v);
	}

	if (yuck_arg->measure.array_arg != NULL) {
		unsigned long v;

		if (!cli_parse_ulong(yuck_arg->read.array_arg, &v)) {
			fputs("Invalid array size.\n", stderr);
			destroy_cli_cmd_measure_arg_from_yuck_arg(arg);
			return NULL;
		}

		arg->array = v;
	} else {
		arg->array = cli_val_list_size(arg->value_list);
	}

	return arg;
}

typedef int (*cli_yuck_cmd_handler)(yuck_t *);

static int cli_yuck_cmd_handler_none(yuck_t *argp)
{
	yuck_auto_help(argp);

	return 0;
}

#define CLI_YUCK_CMD_HANDLER_COMMON(CMD) \
	static int cli_yuck_cmd_handler_##CMD(yuck_t *argp) \
	{ \
		struct cli_cmd_##CMD##_arg *arg = create_cli_cmd_##CMD##_arg_from_yuck_arg(argp); \
\
		if (arg == NULL) { \
			return 1; \
		} \
\
		int exit_code = cli_cmd_##CMD(arg); \
\
		destroy_cli_cmd_##CMD##_arg_from_yuck_arg(arg); \
\
		return exit_code; \
	}

CLI_YUCK_CMD_HANDLER_COMMON(read)
CLI_YUCK_CMD_HANDLER_COMMON(write)
CLI_YUCK_CMD_HANDLER_COMMON(search)
CLI_YUCK_CMD_HANDLER_COMMON(pattern)
CLI_YUCK_CMD_HANDLER_COMMON(freeze)
CLI_YUCK_CMD_HANDLER_COMMON(watch)
CLI_YUCK_CMD_HANDLER_COMMON(execute)
CLI_YUCK_CMD_HANDLER_COMMON(alloc)
CLI_YUCK_CMD_HANDLER_COMMON(dealloc)
CLI_YUCK_CMD_HANDLER_COMMON(measure)

#undef CLI_YUCK_CMD_HANDLER_COMMON

cli_yuck_cmd_handler cli_yuck_cmd_handlers[] = {
	[PROCTAL_CMD_NONE] = cli_yuck_cmd_handler_none,
	[PROCTAL_CMD_READ] = cli_yuck_cmd_handler_read,
	[PROCTAL_CMD_WRITE] = cli_yuck_cmd_handler_write,
	[PROCTAL_CMD_SEARCH] = cli_yuck_cmd_handler_search,
	[PROCTAL_CMD_PATTERN] = cli_yuck_cmd_handler_pattern,
	[PROCTAL_CMD_FREEZE] = cli_yuck_cmd_handler_freeze,
	[PROCTAL_CMD_WATCH] = cli_yuck_cmd_handler_watch,
	[PROCTAL_CMD_EXECUTE] = cli_yuck_cmd_handler_execute,
	[PROCTAL_CMD_ALLOC] = cli_yuck_cmd_handler_alloc,
	[PROCTAL_CMD_DEALLOC] = cli_yuck_cmd_handler_dealloc,
	[PROCTAL_CMD_MEASURE] = cli_yuck_cmd_handler_measure,
};

int main(int argc, char **argv)
{
	yuck_t argp;

	if (yuck_parse(&argp, argc, argv) != 0) {
		// Yuck's error messages are fine for now. Just end it here.
		yuck_free(&argp);
		return 1;
	}

	int exit_code = 0;

	if (argp.help_flag) {
		yuck_auto_help(&argp);
	} else if (argp.version_flag) {
		yuck_auto_version(&argp);
	} else if (argp.cmd < (sizeof cli_yuck_cmd_handlers / sizeof cli_yuck_cmd_handlers[0])) {
		exit_code = cli_yuck_cmd_handlers[argp.cmd](&argp);
	} else {
		fprintf(stderr, "Command not implemented.\n");
		exit_code = 1;
	}

	yuck_free(&argp);

	return exit_code;
}

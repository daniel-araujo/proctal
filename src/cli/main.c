#include <stdio.h>
#include <stdlib.h>

#include "cli/cmd.h"
#include "cli/parser.h"
#include "cli/args.yucc"
#include "magic/magic.h"

#define CLI_DEFAULT_VAL_TYPE CLI_VAL_TYPE_BYTE
#define CLI_DEFAULT_VAL_INTEGER_ENDIANNESS CLI_VAL_INTEGER_ENDIANNESS_LITTLE
#define CLI_DEFAULT_VAL_INTEGER_SIZE CLI_VAL_INTEGER_SIZE_8
#define CLI_DEFAULT_VAL_INTEGER_SIGN CLI_VAL_INTEGER_SIGN_2SCMPL
#define CLI_DEFAULT_VAL_IEEE754_PRECISION CLI_VAL_IEEE754_PRECISION_SINGLE;
#define CLI_DEFAULT_VAL_TEXT_CHARSET CLI_VAL_TEXT_CHARSET_ASCII;
#define CLI_DEFAULT_VAL_INSTRUCTION_ARCH CLI_VAL_INSTRUCTION_ARCH_X86_64;
#define CLI_DEFAULT_CMD_EXECUTE_FORMAT CLI_CMD_EXECUTE_FORMAT_ASSEMBLY;

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
 * Searches for name in an array of strings.
 * Name and options cannot be NULL.
 * Returns the index of the matching name in the array or -1 if not found.
 */
static int index_by_name(char **options, size_t length, const char *name)
{
	for (size_t i = 0; i < length; i++) {
		if (strcmp(options[i], name) == 0) {
			return i;
		}
	}

	return -1;
}

static int cli_val_type_by_name(enum cli_val_type* value, const char *name)
{
	static char *options[] = {
		"byte",
		"integer",
		"ieee754",
		"text",
		"address",
		"instruction",
	};

	static enum cli_val_type values[] = {
		CLI_VAL_TYPE_BYTE,
		CLI_VAL_TYPE_INTEGER,
		CLI_VAL_TYPE_IEEE754,
		CLI_VAL_TYPE_TEXT,
		CLI_VAL_TYPE_ADDRESS,
		CLI_VAL_TYPE_INSTRUCTION,
	};

	int i = index_by_name(options, ARRAY_SIZE(options), name);

	if (i >= 0) {
		*value = values[i];
		return 1;
	} else {
		return 0;
	}
}

static int cli_val_integer_endianness_by_name(enum cli_val_integer_endianness *value, const char *name)
{
	static char *options[] = {
		"little",
	};

	static enum cli_val_integer_endianness values[] = {
		CLI_VAL_INTEGER_ENDIANNESS_LITTLE,
	};

	int i = index_by_name(options, ARRAY_SIZE(options), name);

	if (i >= 0) {
		*value = values[i];
		return 1;
	} else {
		return 0;
	}
}

static int cli_val_integer_size_by_name(enum cli_val_integer_size *value, const char *name)
{
	static char *options[] = {
		"8",
		"16",
		"32",
		"64",
	};

	static enum cli_val_integer_size values[] = {
		CLI_VAL_INTEGER_SIZE_8,
		CLI_VAL_INTEGER_SIZE_16,
		CLI_VAL_INTEGER_SIZE_32,
		CLI_VAL_INTEGER_SIZE_64,
	};

	int i = index_by_name(options, ARRAY_SIZE(options), name);

	if (i >= 0) {
		*value = values[i];
		return 1;
	} else {
		return 0;
	}
}

static int cli_val_integer_sign_by_name(enum cli_val_integer_sign *value, const char *name)
{
	static char *options[] = {
		"unsigned",
		"2scmpl",
	};

	static enum cli_val_integer_sign values[] = {
		CLI_VAL_INTEGER_SIGN_UNSIGNED,
		CLI_VAL_INTEGER_SIGN_2SCMPL,
	};

	int i = index_by_name(options, ARRAY_SIZE(options), name);

	if (i >= 0) {
		*value = values[i];
		return 1;
	} else {
		return 0;
	}
}

static int cli_val_ieee754_precision_by_name(enum cli_val_ieee754_precision *value, const char *name)
{
	static char *options[] = {
		"single",
		"double",
		"extended",
	};

	static enum cli_val_ieee754_precision values[] = {
		CLI_VAL_IEEE754_PRECISION_SINGLE,
		CLI_VAL_IEEE754_PRECISION_DOUBLE,
		CLI_VAL_IEEE754_PRECISION_EXTENDED,
	};

	int i = index_by_name(options, ARRAY_SIZE(options), name);

	if (i >= 0) {
		*value = values[i];
		return 1;
	} else {
		return 0;
	}
}

static int cli_val_text_charset_by_name(enum cli_val_text_charset *value, const char *name)
{
	static char *options[] = {
		"ascii",
	};

	static enum cli_val_text_charset values[] = {
		CLI_VAL_TEXT_CHARSET_ASCII,
	};

	int i = index_by_name(options, ARRAY_SIZE(options), name);

	if (i >= 0) {
		*value = values[i];
		return 1;
	} else {
		return 0;
	}
}

static int cli_val_instruction_arch_by_name(enum cli_val_instruction_arch *value, const char *name)
{
	static char *options[] = {
		"x86-64",
	};

	static enum cli_val_instruction_arch values[] = {
		CLI_VAL_INSTRUCTION_ARCH_X86_64,
	};

	int i = index_by_name(options, ARRAY_SIZE(options), name);

	if (i >= 0) {
		*value = values[i];
		return 1;
	} else {
		return 0;
	}
}

static int cli_cmd_execute_format_by_name(enum cli_cmd_execute_format *value, const char *name)
{
	static char *options[] = {
		"assembly",
		"bytecode",
	};

	static enum cli_cmd_execute_format values[] = {
		CLI_CMD_EXECUTE_FORMAT_ASSEMBLY,
		CLI_CMD_EXECUTE_FORMAT_BYTECODE,
	};

	int i = index_by_name(options, ARRAY_SIZE(options), name);

	if (i >= 0) {
		*value = values[i];
		return 1;
	} else {
		return 0;
	}
}

/*
 * This macro will generate a static inline function that is used to fill up a
 * struct type_arguments based on the arguments given to a yuck argument
 * structure.
 *
 * This is so we can reuse the same code across different yuck argument
 * structures which share the same arguments/options.
 *
 * The function is also responsible for outputting an error message in case of
 * failure.
 *
 * The function returns 1 on success, 0 on failure.
 */
#define CLI_PARSE_TYPE_ARGUMENTS_FROM_YUCK_ARG(NAME, YUCK_TYPE) \
static inline int cli_type_arguments_from_yuck_arg_##NAME(struct type_arguments *type, YUCK_TYPE *yuck_arg) \
{ \
	if (yuck_arg->type_arg) { \
		if (!cli_val_type_by_name(&type->type, yuck_arg->type_arg)) { \
			fputs("Invalid type.\n", stderr); \
			return 0; \
		} \
	} else { \
		type->type = CLI_DEFAULT_VAL_TYPE; \
	} \
\
	switch (type->type) { \
	case CLI_VAL_TYPE_INTEGER: \
		if (yuck_arg->integer_endianness_arg) { \
			if (!cli_val_integer_endianness_by_name(&type->integer_endianness, yuck_arg->integer_endianness_arg)) { \
				fputs("Invalid integer endianness.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->integer_endianness = CLI_DEFAULT_VAL_INTEGER_ENDIANNESS; \
		} \
\
		if (yuck_arg->integer_size_arg) { \
			if (!cli_val_integer_size_by_name(&type->integer_size, yuck_arg->integer_size_arg)) { \
				fputs("Invalid integer size.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->integer_size = CLI_DEFAULT_VAL_INTEGER_SIZE; \
		} \
\
		if (yuck_arg->integer_sign_arg) { \
			if (!cli_val_integer_sign_by_name(&type->integer_sign, yuck_arg->integer_sign_arg)) { \
				fputs("Invalid integer sign.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->integer_sign = CLI_DEFAULT_VAL_INTEGER_SIGN; \
		} \
		break; \
\
	case CLI_VAL_TYPE_IEEE754: \
		if (yuck_arg->ieee754_precision_arg) { \
			if (!cli_val_ieee754_precision_by_name(&type->ieee754_precision, yuck_arg->ieee754_precision_arg)) { \
				fputs("Invalid ieee754 precision.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->ieee754_precision = CLI_DEFAULT_VAL_IEEE754_PRECISION; \
		} \
		break; \
\
	case CLI_VAL_TYPE_TEXT: \
		if (yuck_arg->text_charset_arg) { \
			if (!cli_val_text_charset_by_name(&type->text_charset, yuck_arg->text_charset_arg)) { \
				fputs("Invalid text character set.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->text_charset = CLI_DEFAULT_VAL_TEXT_CHARSET; \
		} \
		break; \
\
	case CLI_VAL_TYPE_INSTRUCTION: \
		if (yuck_arg->instruction_arch_arg) { \
			if (!cli_val_instruction_arch_by_name(&type->instruction_arch, yuck_arg->instruction_arch_arg)) { \
				fputs("Invalid architecture.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->instruction_arch = CLI_DEFAULT_VAL_INSTRUCTION_ARCH; \
		} \
		break; \
	} \
\
	return 1; \
}

CLI_PARSE_TYPE_ARGUMENTS_FROM_YUCK_ARG(read, struct yuck_cmd_read_s)
CLI_PARSE_TYPE_ARGUMENTS_FROM_YUCK_ARG(write, struct yuck_cmd_write_s)
CLI_PARSE_TYPE_ARGUMENTS_FROM_YUCK_ARG(search, struct yuck_cmd_search_s)
CLI_PARSE_TYPE_ARGUMENTS_FROM_YUCK_ARG(measure, struct yuck_cmd_measure_s)

#undef CLI_TYPE_ARGUMENTS_FROM_YUCK_ARG

static void destroy_cli_cmd_read_arg_from_yuck_arg(struct cli_cmd_read_arg *arg)
{
	if (arg->value != cli_val_nil()) {
		cli_val_destroy(arg->value);
	}

	free(arg);
}

static struct cli_cmd_read_arg *create_cli_cmd_read_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_read_arg *arg = malloc(sizeof(*arg));
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
	if (!cli_type_arguments_from_yuck_arg_read(&type_args, &yuck_arg->read)) {
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->value = create_cli_val_from_type_arguments(&type_args);

	if (arg->value == cli_val_nil()) {
		fputs("Invalid type arguments.\n", stderr);
		destroy_cli_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->show_address = yuck_arg->read.show_address_flag == 1;
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
	struct cli_cmd_write_arg *arg = malloc(sizeof(*arg));
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
	if (!cli_type_arguments_from_yuck_arg_write(&type_args, &yuck_arg->write)) {
		destroy_cli_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

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
	struct cli_cmd_search_arg *arg = malloc(sizeof(*arg));
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

	if (yuck_arg->nargs != 0) {
		fputs("This command only accepts options.\n", stderr);
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

	struct type_arguments type_args;
	if (!cli_type_arguments_from_yuck_arg_search(&type_args, &yuck_arg->search)) {
		destroy_cli_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (type_args.type == CLI_VAL_TYPE_INSTRUCTION) {
		fprintf(stderr, "Searching for assembly code is not supported.\n");
		destroy_cli_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

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
	struct cli_cmd_pattern_arg *arg = malloc(sizeof(*arg));

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
	struct cli_cmd_freeze_arg *arg = malloc(sizeof(*arg));

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
	struct cli_cmd_watch_arg *arg = malloc(sizeof(*arg));

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
	struct cli_cmd_execute_arg *arg = malloc(sizeof(*arg));

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

	if (yuck_arg->execute.format_arg) {
		if (!cli_cmd_execute_format_by_name(&arg->format, yuck_arg->execute.format_arg)) {
			fputs("Invalid input format.\n", stderr);
			destroy_cli_cmd_execute_arg_from_yuck_arg(arg);
			return NULL;
		}
	} else {
		arg->format = CLI_DEFAULT_CMD_EXECUTE_FORMAT;
	}

	return arg;
}

static void destroy_cli_cmd_alloc_arg_from_yuck_arg(struct cli_cmd_alloc_arg *arg)
{
	free(arg);
}

static struct cli_cmd_alloc_arg *create_cli_cmd_alloc_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_alloc_arg *arg = malloc(sizeof(*arg));

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
	struct cli_cmd_dealloc_arg *arg = malloc(sizeof(*arg));

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
	struct cli_cmd_measure_arg *arg = malloc(sizeof(*arg));
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
	if (!cli_type_arguments_from_yuck_arg_measure(&type_args, &yuck_arg->measure)) {
		destroy_cli_cmd_measure_arg_from_yuck_arg(arg);
		return NULL;
	}

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

static void destroy_cli_cmd_dump_arg_from_yuck_arg(struct cli_cmd_dump_arg *arg)
{
	free(arg);
}

static struct cli_cmd_dump_arg *create_cli_cmd_dump_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_dump_arg *arg = malloc(sizeof(*arg));

	if (yuck_arg->cmd != PROCTAL_CMD_DUMP) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_dump_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Incorrect number of arguments.\n", stderr);
		destroy_cli_cmd_dump_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->dump.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_dump_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->dump.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_dump_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->read = yuck_arg->dump.read_flag == 1;
	arg->write = yuck_arg->dump.write_flag == 1;
	arg->execute = yuck_arg->dump.execute_flag == 1;
	arg->program_code = yuck_arg->dump.program_code_flag == 1;

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
CLI_YUCK_CMD_HANDLER_COMMON(dump)

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
	[PROCTAL_CMD_DUMP] = cli_yuck_cmd_handler_dump,
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
	} else if (argp.cmd < ARRAY_SIZE(cli_yuck_cmd_handlers)) {
		exit_code = cli_yuck_cmd_handlers[argp.cmd](&argp);
	} else {
		fprintf(stderr, "Command not implemented.\n");
		exit_code = 1;
	}

	yuck_free(&argp);

	return exit_code;
}

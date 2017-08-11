#include <stdio.h>
#include <stdlib.h>
#include <darr.h>

#include "cli/yuck/main.h"
#include "cli/cmd/allocate.h"
#include "cli/cmd/deallocate.h"
#include "cli/cmd/dump.h"
#include "cli/cmd/execute.h"
#include "cli/cmd/freeze.h"
#include "cli/cmd/measure.h"
#include "cli/cmd/pattern.h"
#include "cli/cmd/read.h"
#include "cli/cmd/search.h"
#include "cli/cmd/watch.h"
#include "cli/cmd/write.h"
#include "cli/parser.h"
#include "cli/assembler.h"
#include "cli/yuck/args.yucc"
#include "magic/magic.h"

#define DEFAULT_VAL_TYPE CLI_VAL_TYPE_BYTE
#define DEFAULT_VAL_IEEE754_PRECISION CLI_VAL_IEEE754_PRECISION_SINGLE;
#define DEFAULT_VAL_TEXT_ENCODING CLI_VAL_TEXT_ENCODING_ASCII;
#define DEFAULT_CMD_EXECUTE_FORMAT CLI_CMD_EXECUTE_FORMAT_ASSEMBLY;

/*
 * This structure contains all type options parsed.
 */
struct type_options {
	enum cli_val_type type;
	enum cli_val_integer_endianness integer_endianness;
	enum cli_val_integer_sign integer_sign;
	enum cli_val_integer_size integer_size;
	enum cli_val_ieee754_precision ieee754_precision;
	enum cli_val_text_encoding text_encoding;
	enum cli_val_instruction_architecture instruction_architecture;
	enum cli_val_instruction_syntax instruction_syntax;
};

/*
 * Creates a cli_val from a struct type_options. You only have to have
 * initialized the data members that are relevant to the type.
 *
 * You are expected to keep track of the life time of the returned cli_val.
 *
 * Returns a nil value on failure.
 */
static cli_val create_cli_val_from_type_options(struct type_options *ta)
{
	switch (ta->type) {
	case CLI_VAL_TYPE_INTEGER: {
		struct cli_val_integer_attr a;
		cli_val_integer_attr_init(&a);
		cli_val_integer_attr_size_set(&a, ta->integer_size);
		cli_val_integer_attr_sign_set(&a, ta->integer_sign);
		cli_val_integer_attr_endianness_set(&a, ta->integer_endianness);

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
		cli_val_ieee754_attr_precision_set(&a, ta->ieee754_precision);

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
		cli_val_text_attr_encoding_set(&a, ta->text_encoding);

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
		cli_val_instruction_attr_architecture_set(&a, ta->instruction_architecture);
		cli_val_instruction_attr_syntax_set(&a, ta->instruction_syntax);

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

	case CLI_VAL_TYPE_NIL:
		break;
	}

	return cli_val_nil();
}

/*
 * Parse values
 *
 * This is so we can reuse the same code across different yuck argument
 * structures which share the same options.
 *
 * The function is also responsible for outputting an error message in case of
 * failure.
 *
 * The function returns 1 on success, 0 on failure.
 */
static int create_cli_val_list_from_type_options(struct type_options *ta, void *address, char **args, size_t length, struct darr *values)
{
	int ret = 0;

	// Initial size will be the number of arguments.
	darr_resize(values, length);

	size_t next = 0;

	char *vaddress = address;
	for (size_t i = 0; i < length; ++i) {
		cli_val v = create_cli_val_from_type_options(ta);

		if (v == cli_val_nil()) {
			fputs("Invalid type options or out of memory.\n", stderr);
			goto exit1;
		}

		cli_val_address_set(v, vaddress);

		if (!cli_val_parse_text(v, args[i])) {
			fprintf(stderr, "Value #%zu is invalid.\n", i + 1);
			cli_val_destroy(v);
			goto exit1;
		}

		vaddress += cli_val_sizeof(v);

		cli_val *e = darr_element(values, next++);
		*e = v;

		if (next >= darr_size(values)) {
			darr_grow(values, darr_size(values));
		}
	}

	ret = 1;
exit1:
	darr_resize(values, next);
exit0:
	return ret;
}

static void destroy_cli_val_list(struct darr *list)
{
	for (cli_val *e = darr_begin(list); e != darr_end(list); ++e) {
		cli_val_destroy(*e);
	}
}

/*
 * This macro will generate a static inline function that is used to fill up a
 * struct type_options based on the arguments given to a yuck argument
 * structure.
 *
 * This is so we can reuse the same code across different yuck argument
 * structures which share the same options.
 *
 * The function is also responsible for outputting an error message in case of
 * failure.
 *
 * The function returns 1 on success, 0 on failure.
 */
#define CLI_PARSE_TYPE_OPTIONS(NAME, YUCK_TYPE) \
static inline int cli_type_options_##NAME(struct type_options *type, YUCK_TYPE *yuck_arg) \
{ \
	if (yuck_arg->type_arg) { \
		if (!cli_parse_val_type(yuck_arg->type_arg, &type->type)) { \
			fputs("Invalid type.\n", stderr); \
			return 0; \
		} \
	} else { \
		type->type = DEFAULT_VAL_TYPE; \
	} \
\
	switch (type->type) { \
	case CLI_VAL_TYPE_INTEGER: \
		if (yuck_arg->integer_endianness_arg) { \
			if (!cli_parse_val_integer_endianness(yuck_arg->integer_endianness_arg, &type->integer_endianness)) { \
				fputs("Invalid integer endianness.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->integer_endianness = CLI_VAL_INTEGER_ENDIANNESS_DEFAULT; \
		} \
\
		if (yuck_arg->integer_size_arg) { \
			if (!cli_parse_val_integer_size(yuck_arg->integer_size_arg, &type->integer_size)) { \
				fputs("Invalid integer size.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->integer_size = CLI_VAL_INTEGER_SIZE_DEFAULT; \
		} \
\
		if (yuck_arg->integer_sign_arg) { \
			if (!cli_parse_val_integer_sign(yuck_arg->integer_sign_arg, &type->integer_sign)) { \
				fputs("Invalid integer sign.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->integer_sign = CLI_VAL_INTEGER_SIGN_DEFAULT; \
		} \
		break; \
\
	case CLI_VAL_TYPE_IEEE754: \
		if (yuck_arg->ieee754_precision_arg) { \
			if (!cli_parse_val_ieee754_precision(yuck_arg->ieee754_precision_arg, &type->ieee754_precision)) { \
				fputs("Invalid ieee754 precision.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->ieee754_precision = DEFAULT_VAL_IEEE754_PRECISION; \
		} \
		break; \
\
	case CLI_VAL_TYPE_TEXT: \
		if (yuck_arg->text_encoding_arg) { \
			if (!cli_parse_val_text_encoding(yuck_arg->text_encoding_arg, &type->text_encoding)) { \
				fputs("Invalid text encoding.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->text_encoding = DEFAULT_VAL_TEXT_ENCODING; \
		} \
		break; \
\
	case CLI_VAL_TYPE_INSTRUCTION: \
		if (yuck_arg->instruction_architecture_arg) { \
			if (!cli_parse_val_instruction_architecture(yuck_arg->instruction_architecture_arg, &type->instruction_architecture)) { \
				fputs("Invalid architecture.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->instruction_architecture = CLI_VAL_INSTRUCTION_ARCHITECTURE_DEFAULT; \
		} \
\
		if (yuck_arg->instruction_syntax_arg) { \
			if (!cli_parse_val_instruction_syntax(yuck_arg->instruction_syntax_arg, &type->instruction_syntax)) { \
				fputs("Invalid assembly syntax.\n", stderr); \
				return 0; \
			} \
		} else { \
			type->instruction_syntax = CLI_VAL_INSTRUCTION_SYNTAX_DEFAULT; \
		} \
		break; \
\
	case CLI_VAL_TYPE_BYTE: \
	case CLI_VAL_TYPE_ADDRESS: \
		break; \
\
	default: \
		fputs("Unknown type.\n", stderr); \
		return 0; \
	} \
\
	return 1; \
}

CLI_PARSE_TYPE_OPTIONS(read, struct yuck_cmd_read_s)
CLI_PARSE_TYPE_OPTIONS(write, struct yuck_cmd_write_s)
CLI_PARSE_TYPE_OPTIONS(search, struct yuck_cmd_search_s)
CLI_PARSE_TYPE_OPTIONS(measure, struct yuck_cmd_measure_s)

#undef CLI_TYPE_OPTIONS

static void destroy_cli_cmd_read_arg(struct cli_cmd_read_arg *arg)
{
	if (arg->value != cli_val_nil()) {
		cli_val_destroy(arg->value);
	}

	free(arg);
}

static struct cli_cmd_read_arg *create_cli_cmd_read_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_read_arg *arg = malloc(sizeof(*arg));
	arg->freeze = yuck_arg->read.freeze_flag == 1;
	arg->value = cli_val_nil();

	if (yuck_arg->cmd != PROCTAL_CMD_READ) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_read_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Wrong number of arguments.\n", stderr);
		destroy_cli_cmd_read_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_read_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->read.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_read_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_cli_cmd_read_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->read.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_read_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.array_arg != NULL) {
		unsigned long v;

		if (!cli_parse_unsigned_long(yuck_arg->read.array_arg, &v)) {
			fputs("Invalid array size.\n", stderr);
			destroy_cli_cmd_read_arg(arg);
			return NULL;
		}

		arg->array = v;
	} else {
		arg->array = 1;
	}

	struct type_options type_args;
	if (!cli_type_options_read(&type_args, &yuck_arg->read)) {
		destroy_cli_cmd_read_arg(arg);
		return NULL;
	}

	arg->value = create_cli_val_from_type_options(&type_args);

	if (arg->value == cli_val_nil()) {
		fputs("Invalid type options.\n", stderr);
		destroy_cli_cmd_read_arg(arg);
		return NULL;
	}

	arg->show_address = yuck_arg->read.show_address_flag == 1;
	arg->show_bytes = yuck_arg->read.show_bytes_flag == 1;

	return arg;
}

static void destroy_cli_cmd_write_arg(struct cli_cmd_write_arg *arg)
{
	destroy_cli_val_list(&arg->values);
	darr_deinit(&arg->values);
	free(arg);
}

static struct cli_cmd_write_arg *create_cli_cmd_write_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_write_arg *arg = malloc(sizeof(*arg));
	arg->freeze = yuck_arg->write.freeze_flag == 1;
	darr_init(&arg->values, sizeof(cli_val));

	if (yuck_arg->cmd != PROCTAL_CMD_WRITE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_write_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs == 0) {
		fputs("You must provide at least 1 value.\n", stderr);
		destroy_cli_cmd_write_arg(arg);
		return NULL;
	}

	if (yuck_arg->write.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_write_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->write.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_write_arg(arg);
		return NULL;
	}

	if (yuck_arg->write.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_cli_cmd_write_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->write.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_write_arg(arg);
		return NULL;
	}

	struct type_options type_args;
	if (!cli_type_options_write(&type_args, &yuck_arg->write)) {
		destroy_cli_cmd_write_arg(arg);
		return NULL;
	}

	if (!create_cli_val_list_from_type_options(&type_args, arg->address, yuck_arg->args, yuck_arg->nargs, &arg->values)) {
		destroy_cli_cmd_write_arg(arg);
		return NULL;
	}

	if (yuck_arg->write.array_arg != NULL) {
		unsigned long v;

		if (!cli_parse_unsigned_long(yuck_arg->read.array_arg, &v)) {
			fputs("Invalid array size.\n", stderr);
			destroy_cli_cmd_write_arg(arg);
			return NULL;
		}

		arg->array = v;
	} else {
		arg->array = darr_size(&arg->values);
	}

	if (yuck_arg->write.repeat_flag) {
		arg->repeat = 1;

		if (yuck_arg->write.repeat_delay_arg) {
			if (!cli_parse_int(yuck_arg->write.repeat_delay_arg, &arg->repeat_delay)) {
				fputs("Invalid repeat delay.\n", stderr);
				destroy_cli_cmd_write_arg(arg);
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

static void destroy_cli_cmd_search_arg(struct cli_cmd_search_arg *arg)
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

static struct cli_cmd_search_arg *create_cli_cmd_search_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_search_arg *arg = malloc(sizeof(*arg));
	arg->freeze = yuck_arg->search.freeze_flag == 1;
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
		destroy_cli_cmd_search_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("This command only accepts options.\n", stderr);
		destroy_cli_cmd_search_arg(arg);
		return NULL;
	}

	if (yuck_arg->search.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_search_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->search.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_search_arg(arg);
		return NULL;
	}

	struct type_options type_args;
	if (!cli_type_options_search(&type_args, &yuck_arg->search)) {
		destroy_cli_cmd_search_arg(arg);
		return NULL;
	}

	if (type_args.type == CLI_VAL_TYPE_INSTRUCTION) {
		fprintf(stderr, "Searching for assembly code is not supported.\n");
		destroy_cli_cmd_search_arg(arg);
		return NULL;
	}

	arg->value = create_cli_val_from_type_options(&type_args);

	if (arg->value == cli_val_nil()) {
		fputs("Invalid type options.\n", stderr);
		destroy_cli_cmd_search_arg(arg);
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
		destroy_cli_cmd_search_arg(arg); \
		return NULL; \
	}

	FORCE_POSITIVE(inc);
	FORCE_POSITIVE(inc_up_to);
	FORCE_POSITIVE(dec);
	FORCE_POSITIVE(dec_up_to);

#define GET_COMPARE_ARG(NAME) \
	if (yuck_arg->search.NAME##_arg != NULL) { \
		arg->NAME = 1; \
		arg->NAME##_value = create_cli_val_from_type_options(&type_args); \
		if (!cli_val_parse_text(arg->NAME##_value, yuck_arg->search.NAME##_arg)) { \
			fputs("Invalid value for --"#NAME".\n", stderr); \
			destroy_cli_cmd_search_arg(arg); \
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

static void destroy_cli_cmd_pattern_arg(struct cli_cmd_pattern_arg *arg)
{
	free(arg);
}

static struct cli_cmd_pattern_arg *create_cli_cmd_pattern_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_pattern_arg *arg = malloc(sizeof(*arg));
	arg->freeze = yuck_arg->pattern.freeze_flag == 1;

	if (yuck_arg->cmd != PROCTAL_CMD_PATTERN) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_pattern_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 1) {
		fputs("Incorrect number of arguments.\n", stderr);
		destroy_cli_cmd_pattern_arg(arg);
		return NULL;
	}

	if (yuck_arg->pattern.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_pattern_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->pattern.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_pattern_arg(arg);
		return NULL;
	}

	arg->pattern = yuck_arg->args[0];

	arg->read = yuck_arg->pattern.read_flag == 1;
	arg->write = yuck_arg->pattern.write_flag == 1;
	arg->execute = yuck_arg->pattern.execute_flag == 1;
	arg->program_code = yuck_arg->pattern.program_code_flag == 1;

	return arg;
}

static void destroy_cli_cmd_freeze_arg(struct cli_cmd_freeze_arg *arg)
{
	free(arg);
}

static struct cli_cmd_freeze_arg *create_cli_cmd_freeze_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_freeze_arg *arg = malloc(sizeof(*arg));

	if (yuck_arg->cmd != PROCTAL_CMD_FREEZE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_freeze_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Too many arguments.\n", stderr);
		destroy_cli_cmd_freeze_arg(arg);
		return NULL;
	}

	if (yuck_arg->freeze.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_freeze_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->freeze.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_freeze_arg(arg);
		return NULL;
	}

	arg->input = yuck_arg->freeze.input_flag == 1;

	return arg;
}

static void destroy_cli_cmd_watch_arg(struct cli_cmd_watch_arg *arg)
{
	free(arg);
}

static struct cli_cmd_watch_arg *create_cli_cmd_watch_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_watch_arg *arg = malloc(sizeof(*arg));

	if (yuck_arg->cmd != PROCTAL_CMD_WATCH) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_watch_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Too many arguments.\n", stderr);
		destroy_cli_cmd_watch_arg(arg);
		return NULL;
	}

	if (yuck_arg->watch.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_watch_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->watch.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_watch_arg(arg);
		return NULL;
	}

	if (yuck_arg->watch.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_cli_cmd_watch_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->watch.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_watch_arg(arg);
		return NULL;
	}

	arg->read = yuck_arg->watch.read_flag == 1;
	arg->write = yuck_arg->watch.write_flag == 1;
	arg->execute = yuck_arg->watch.execute_flag == 1;
	arg->unique = yuck_arg->watch.unique_flag == 1;

	return arg;
}

static void destroy_cli_cmd_execute_arg(struct cli_cmd_execute_arg *arg)
{
	free(arg);
}

static struct cli_cmd_execute_arg *create_cli_cmd_execute_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_execute_arg *arg = malloc(sizeof(*arg));

	if (yuck_arg->cmd != PROCTAL_CMD_EXECUTE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_execute_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Too many arguments.\n", stderr);
		destroy_cli_cmd_execute_arg(arg);
		return NULL;
	}

	if (yuck_arg->execute.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_execute_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->execute.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_execute_arg(arg);
		return NULL;
	}

	if (yuck_arg->execute.format_arg) {
		if (!cli_parse_cmd_execute_format(yuck_arg->execute.format_arg, &arg->format)) {
			fputs("Invalid input format.\n", stderr);
			destroy_cli_cmd_execute_arg(arg);
			return NULL;
		}
	} else {
		arg->format = DEFAULT_CMD_EXECUTE_FORMAT;
	}

	if (arg->format == CLI_CMD_EXECUTE_FORMAT_ASSEMBLY) {
		if (yuck_arg->execute.assembly_architecture_arg) {
			if (!cli_parse_assembler_architecture(yuck_arg->execute.assembly_architecture_arg, &arg->assembly_architecture)) {
				fputs("Invalid architecture.\n", stderr);
				return 0;
			}
		} else {
			arg->assembly_architecture = CLI_ASSEMBLER_ARCHITECTURE_DEFAULT;
		}

		if (yuck_arg->execute.assembly_syntax_arg) {
			if (!cli_parse_assembler_syntax(yuck_arg->execute.assembly_syntax_arg, &arg->assembly_syntax)) {
				fputs("Invalid assembly syntax.\n", stderr);
				return 0;
			}
		} else {
			arg->assembly_syntax = CLI_ASSEMBLER_SYNTAX_DEFAULT;
		}
	}

	return arg;
}

static void destroy_cli_cmd_allocate_arg(struct cli_cmd_allocate_arg *arg)
{
	free(arg);
}

static struct cli_cmd_allocate_arg *create_cli_cmd_allocate_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_allocate_arg *arg = malloc(sizeof(*arg));

	if (yuck_arg->cmd != PROCTAL_CMD_ALLOCATE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_allocate_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 1) {
		fputs("Incorrect number of arguments.\n", stderr);
		destroy_cli_cmd_allocate_arg(arg);
		return NULL;
	}

	if (!cli_parse_unsigned_long(yuck_arg->args[0], &arg->size)) {
		fputs("Invalid size.\n", stderr);
		destroy_cli_cmd_allocate_arg(arg);
		return NULL;
	}

	if (yuck_arg->allocate.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_allocate_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->allocate.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_allocate_arg(arg);
		return NULL;
	}

	arg->read = yuck_arg->allocate.read_flag == 1;
	arg->write = yuck_arg->allocate.write_flag == 1;
	arg->execute = yuck_arg->allocate.execute_flag == 1;

	return arg;
}

static void destroy_cli_cmd_deallocate_arg(struct cli_cmd_deallocate_arg *arg)
{
	free(arg);
}

static struct cli_cmd_deallocate_arg *create_cli_cmd_deallocate_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_deallocate_arg *arg = malloc(sizeof(*arg));

	if (yuck_arg->cmd != PROCTAL_CMD_DEALLOCATE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_deallocate_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 1) {
		fputs("Incorrect number of arguments.\n", stderr);
		destroy_cli_cmd_deallocate_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->args[0], &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_deallocate_arg(arg);
		return NULL;
	}

	if (yuck_arg->deallocate.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_deallocate_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->deallocate.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_deallocate_arg(arg);
		return NULL;
	}

	return arg;
}

static void destroy_cli_cmd_measure_arg(struct cli_cmd_measure_arg *arg)
{
	destroy_cli_val_list(&arg->values);
	darr_deinit(&arg->values);
	free(arg);
}

static struct cli_cmd_measure_arg *create_cli_cmd_measure_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_measure_arg *arg = malloc(sizeof(*arg));
	darr_init(&arg->values, sizeof(cli_val));

	if (yuck_arg->cmd != PROCTAL_CMD_MEASURE) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_measure_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs == 0) {
		fputs("You must provide at least 1 value.\n", stderr);
		destroy_cli_cmd_measure_arg(arg);
		return NULL;
	}

	if (yuck_arg->measure.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_cli_cmd_measure_arg(arg);
		return NULL;
	}

	if (!cli_parse_address(yuck_arg->measure.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_cli_cmd_measure_arg(arg);
		return NULL;
	}

	struct type_options type_args;
	if (!cli_type_options_measure(&type_args, &yuck_arg->measure)) {
		destroy_cli_cmd_measure_arg(arg);
		return NULL;
	}

	if (!create_cli_val_list_from_type_options(&type_args, arg->address, yuck_arg->args, yuck_arg->nargs, &arg->values)) {
		destroy_cli_cmd_measure_arg(arg);
		return NULL;
	}

	if (yuck_arg->measure.array_arg != NULL) {
		unsigned long v;

		if (!cli_parse_unsigned_long(yuck_arg->read.array_arg, &v)) {
			fputs("Invalid array size.\n", stderr);
			destroy_cli_cmd_measure_arg(arg);
			return NULL;
		}

		arg->array = v;
	} else {
		arg->array = darr_size(&arg->values);
	}

	return arg;
}

static void destroy_cli_cmd_dump_arg(struct cli_cmd_dump_arg *arg)
{
	free(arg);
}

static struct cli_cmd_dump_arg *create_cli_cmd_dump_arg(yuck_t *yuck_arg)
{
	struct cli_cmd_dump_arg *arg = malloc(sizeof(*arg));
	arg->freeze = yuck_arg->dump.freeze_flag == 1;

	if (yuck_arg->cmd != PROCTAL_CMD_DUMP) {
		fputs("Wrong command.\n", stderr);
		destroy_cli_cmd_dump_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Incorrect number of arguments.\n", stderr);
		destroy_cli_cmd_dump_arg(arg);
		return NULL;
	}

	if (yuck_arg->dump.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_cli_cmd_dump_arg(arg);
		return NULL;
	}

	if (!cli_parse_int(yuck_arg->dump.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_cli_cmd_dump_arg(arg);
		return NULL;
	}

	arg->read = yuck_arg->dump.read_flag == 1;
	arg->write = yuck_arg->dump.write_flag == 1;
	arg->execute = yuck_arg->dump.execute_flag == 1;
	arg->program_code = yuck_arg->dump.program_code_flag == 1;

	return arg;
}


typedef int (*cmd_handler)(yuck_t *);

static int cmd_handler_none(yuck_t *argp)
{
	yuck_auto_help(argp);

	return 0;
}

#define CMD_HANDLER_COMMON(CMD) \
	static int cmd_handler_##CMD(yuck_t *argp) \
	{ \
		struct cli_cmd_##CMD##_arg *arg = create_cli_cmd_##CMD##_arg(argp); \
\
		if (arg == NULL) { \
			return 1; \
		} \
\
		int exit_code = cli_cmd_##CMD(arg); \
\
		destroy_cli_cmd_##CMD##_arg(arg); \
\
		return exit_code; \
	}

CMD_HANDLER_COMMON(read)
CMD_HANDLER_COMMON(write)
CMD_HANDLER_COMMON(search)
CMD_HANDLER_COMMON(pattern)
CMD_HANDLER_COMMON(freeze)
CMD_HANDLER_COMMON(watch)
CMD_HANDLER_COMMON(execute)
CMD_HANDLER_COMMON(allocate)
CMD_HANDLER_COMMON(deallocate)
CMD_HANDLER_COMMON(measure)
CMD_HANDLER_COMMON(dump)

#undef CMD_HANDLER_COMMON

cmd_handler cmd_handlers[] = {
	[PROCTAL_CMD_NONE] = cmd_handler_none,
	[PROCTAL_CMD_READ] = cmd_handler_read,
	[PROCTAL_CMD_WRITE] = cmd_handler_write,
	[PROCTAL_CMD_SEARCH] = cmd_handler_search,
	[PROCTAL_CMD_PATTERN] = cmd_handler_pattern,
	[PROCTAL_CMD_FREEZE] = cmd_handler_freeze,
	[PROCTAL_CMD_WATCH] = cmd_handler_watch,
	[PROCTAL_CMD_EXECUTE] = cmd_handler_execute,
	[PROCTAL_CMD_ALLOCATE] = cmd_handler_allocate,
	[PROCTAL_CMD_DEALLOCATE] = cmd_handler_deallocate,
	[PROCTAL_CMD_MEASURE] = cmd_handler_measure,
	[PROCTAL_CMD_DUMP] = cmd_handler_dump,
};

int cli_yuck_main(int argc, char **argv)
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
	} else if (argp.cmd < ARRAY_SIZE(cmd_handlers)) {
		exit_code = cmd_handlers[argp.cmd](&argp);
	} else {
		fprintf(stderr, "Command not implemented.\n");
		exit_code = 1;
	}

	yuck_free(&argp);

	return exit_code;
}

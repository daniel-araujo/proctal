#include <stdio.h>
#include <stdlib.h>
#include <proctal.h>

#include "cmd.h"
#include "parser.h"
#include "args.yucc"

#define PARSE_TYPE_ATTRIBUTES(ATTR, YUCK) \
	proctal_cmd_val_attr_set_endianness(ATTR, proctal_cmd_val_type_endianness_by_name(YUCK.endianness_arg)); \
\
	switch (t) { \
	case PROCTAL_CMD_VAL_TYPE_INTEGER: \
		proctal_cmd_val_attr_set_integer_size(ATTR, proctal_cmd_val_type_integer_size_by_name(YUCK.integer_size_arg)); \
		proctal_cmd_val_attr_set_integer_sign(ATTR, proctal_cmd_val_type_integer_sign_by_name(YUCK.integer_sign_arg)); \
		break; \
\
	case PROCTAL_CMD_VAL_TYPE_IEEE754: \
		proctal_cmd_val_attr_set_ieee754_precision(ATTR, proctal_cmd_val_type_ieee754_precision_by_name(YUCK.ieee754_precision_arg)); \
		break; \
\
	case PROCTAL_CMD_VAL_TYPE_TEXT: \
		proctal_cmd_val_attr_set_text_charset(ATTR, proctal_cmd_val_type_text_charset_by_name(YUCK.text_charset_arg)); \
		break; \
	}

struct value_options {
	const char *name;
	void* value;
};

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

static enum proctal_cmd_val_type proctal_cmd_val_type_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "byte",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_BYTE,
		},
		{
			.name = "integer",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_INTEGER,
		},
		{
			.name = "ieee754",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_IEEE754,
		},
		{
			.name = "text",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_TEXT,
		},
		{
			.name = "address",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_ADDRESS,
		},
	};

	return (enum proctal_cmd_val_type) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) PROCTAL_CMD_VAL_TYPE_BYTE);
}

static enum proctal_cmd_val_type_endianness proctal_cmd_val_type_endianness_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "little",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_ENDIANNESS_LITTLE,
		},
	};

	return (enum proctal_cmd_val_type_integer_size) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) PROCTAL_CMD_VAL_TYPE_ENDIANNESS_LITTLE);
}

static enum proctal_cmd_val_type_integer_size proctal_cmd_val_type_integer_size_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "8",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8,
		},
		{
			.name = "16",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16,
		},
		{
			.name = "32",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32,
		},
		{
			.name = "64",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64,
		},
	};

	return (enum proctal_cmd_val_type_integer_size) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8);
}

static enum proctal_cmd_val_type_integer_sign proctal_cmd_val_type_integer_sign_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "unsigned",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED,
		},
		{
			.name = "2scmpl",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_2SCMPL,
		},
	};

	return (enum proctal_cmd_val_type_integer_sign) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_2SCMPL);
}

static enum proctal_cmd_val_type_ieee754_precision proctal_cmd_val_type_ieee754_precision_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "single",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE,
		},
		{
			.name = "double",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE,
		},
		{
			.name = "extended",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED,
		},
	};

	return (enum proctal_cmd_val_type_ieee754_precision) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE);
}

static enum proctal_cmd_val_type_text_charset proctal_cmd_val_type_text_charset_by_name(const char *name)
{
	static struct value_options options[] = {
		{
			.name = "ascii",
			.value = (void *) PROCTAL_CMD_VAL_TYPE_TEXT_CHARSET_ASCII,
		},
	};

	return (enum proctal_cmd_val_type_text_charset) value_by_name(
		options,
		sizeof options / sizeof options[0],
		name,
		(void *) PROCTAL_CMD_VAL_TYPE_TEXT_CHARSET_ASCII);
}

static void destroy_proctal_cmd_read_arg_from_yuck_arg(struct proctal_cmd_read_arg *arg)
{
	if (arg->value_attr) {
		proctal_cmd_val_attr_destroy(arg->value_attr);
	}

	free(arg);
}

static struct proctal_cmd_read_arg *create_proctal_cmd_read_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct proctal_cmd_read_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_READ) {
		fputs("Wrong command.\n", stderr);
		destroy_proctal_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Wrong number of arguments.\n", stderr);
		destroy_proctal_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_proctal_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!proctal_cmd_parse_int(yuck_arg->read.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_proctal_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_proctal_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!proctal_cmd_parse_address(yuck_arg->read.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_proctal_cmd_read_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->read.array_arg != NULL) {
		if (!proctal_cmd_parse_int(yuck_arg->read.array_arg, (int *) &arg->array)) {
			fputs("Invalid array size.\n", stderr);
			destroy_proctal_cmd_read_arg_from_yuck_arg(arg);
			return NULL;
		}
	} else {
		arg->array = 1;
	}

	enum proctal_cmd_val_type t = proctal_cmd_val_type_by_name(yuck_arg->read.type_arg);
	arg->value_attr = proctal_cmd_val_attr_create(t);

	PARSE_TYPE_ATTRIBUTES(arg->value_attr, yuck_arg->read)

	return arg;
}

static void destroy_proctal_cmd_write_arg_from_yuck_arg(struct proctal_cmd_write_arg *arg)
{
	if (arg->first_value) {
		for (size_t i = 0; arg->first_value + i != arg->end_value; ++i) {
			proctal_cmd_val_destroy(arg->first_value[i]);
		}

		free(arg->first_value);
	}

	free(arg);
}

static struct proctal_cmd_write_arg *create_proctal_cmd_write_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct proctal_cmd_write_arg *arg = malloc(sizeof *arg);
	arg->first_value = NULL;
	arg->end_value = NULL;

	if (yuck_arg->cmd != PROCTAL_CMD_WRITE) {
		fputs("Wrong command.\n", stderr);
		destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->nargs == 0) {
		fputs("You must provide at least 1 value.\n", stderr);
		destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->write.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!proctal_cmd_parse_int(yuck_arg->write.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->write.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!proctal_cmd_parse_address(yuck_arg->write.address_arg, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	enum proctal_cmd_val_type t = proctal_cmd_val_type_by_name(yuck_arg->write.type_arg);
	proctal_cmd_val_attr value_attr = proctal_cmd_val_attr_create(t);

	PARSE_TYPE_ATTRIBUTES(value_attr, yuck_arg->write)

	arg->first_value = malloc(sizeof (proctal_cmd_val) + yuck_arg->nargs);

	if (arg->first_value == NULL) {
		fputs("Failed to allocate memory for values.\n", stderr);
		proctal_cmd_val_attr_destroy(value_attr);
		destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
		return NULL;
	}

	arg->end_value = arg->first_value;
	for (size_t i = 0; i < yuck_arg->nargs; ++i) {
		 proctal_cmd_val v = proctal_cmd_val_create(value_attr);

		if (!proctal_cmd_val_parse(v, yuck_arg->args[i])) {
			fprintf(stderr, "Value #%zu is invalid.\n", i);
			proctal_cmd_val_attr_destroy(value_attr);
			destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
			return NULL;
		}

		arg->first_value[i] = v;
		arg->end_value = arg->first_value + i + 1;
	}

	proctal_cmd_val_attr_destroy(value_attr);

	if (yuck_arg->read.array_arg != NULL) {
		if (!proctal_cmd_parse_int(yuck_arg->write.array_arg, (int *) &arg->array)) {
			fputs("Invalid array size.\n", stderr);
			destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
			return NULL;
		}
	} else {
		arg->array = arg->end_value - arg->first_value;
	}

	if (yuck_arg->write.repeat_flag) {
		arg->repeat = 1;

		if (yuck_arg->write.repeat_delay_arg) {
			if (!proctal_cmd_parse_int(yuck_arg->write.repeat_delay_arg, &arg->repeat_delay)) {
				fputs("Invalid repeat delay.\n", stderr);
				destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
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

static void destroy_proctal_cmd_search_arg_from_yuck_arg(struct proctal_cmd_search_arg *arg)
{
	if (arg->value_attr) {
		proctal_cmd_val_attr_destroy(arg->value_attr);
	}

#define DESTROY_COMPARE_ARG(PROCTALNAME) \
	if (arg->PROCTALNAME) { \
		free(arg->PROCTALNAME##_value); \
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

static struct proctal_cmd_search_arg *create_proctal_cmd_search_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct proctal_cmd_search_arg *arg = malloc(sizeof *arg);
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

	if (yuck_arg->cmd != PROCTAL_CMD_SEARCH) {
		fputs("Wrong command.\n", stderr);
		destroy_proctal_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (yuck_arg->search.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		destroy_proctal_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	if (!proctal_cmd_parse_int(yuck_arg->search.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		destroy_proctal_cmd_search_arg_from_yuck_arg(arg);
		return NULL;
	}

	enum proctal_cmd_val_type t = proctal_cmd_val_type_by_name(yuck_arg->search.type_arg);
	arg->value_attr = proctal_cmd_val_attr_create(t);

	PARSE_TYPE_ATTRIBUTES(arg->value_attr, yuck_arg->search)

	if (yuck_arg->search.input_flag) {
		arg->input = 1;
	}

#define FORCE_POSITIVE(NAME) \
	if (yuck_arg->search.NAME##_arg != NULL \
		&& (strcmp("0", yuck_arg->search.NAME##_arg) == 0 \
			|| strncmp("-", yuck_arg->search.NAME##_arg, 1) == 0)) { \
		fputs("Value must be positive for --"#NAME".\n", stderr); \
		destroy_proctal_cmd_search_arg_from_yuck_arg(arg); \
		return NULL; \
	}

	FORCE_POSITIVE(inc);
	FORCE_POSITIVE(inc_up_to);
	FORCE_POSITIVE(dec);
	FORCE_POSITIVE(dec_up_to);

#define GET_COMPARE_ARG(NAME) \
	if (yuck_arg->search.NAME##_arg != NULL) { \
		arg->NAME = 1; \
		arg->NAME##_value = proctal_cmd_val_create(arg->value_attr); \
		if (!proctal_cmd_val_parse(arg->NAME##_value, yuck_arg->search.NAME##_arg)) { \
			fputs("Invalid value for --"#NAME".\n", stderr); \
			destroy_proctal_cmd_search_arg_from_yuck_arg(arg); \
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
	} else if (argp.cmd == YUCK_NOCMD) {
		yuck_auto_help(&argp);
	} else if (argp.cmd == PROCTAL_CMD_WRITE) {
		struct proctal_cmd_write_arg *arg = create_proctal_cmd_write_arg_from_yuck_arg(&argp);

		if (arg == NULL) {
			yuck_free(&argp);
			return 1;
		}

		exit_code = proctal_cmd_write(arg);

		destroy_proctal_cmd_write_arg_from_yuck_arg(arg);
	} else if (argp.cmd == PROCTAL_CMD_READ) {
		struct proctal_cmd_read_arg *arg = create_proctal_cmd_read_arg_from_yuck_arg(&argp);

		if (arg == NULL) {
			yuck_free(&argp);
			return 1;
		}

		exit_code = proctal_cmd_read(arg);

		destroy_proctal_cmd_read_arg_from_yuck_arg(arg);
	} else if (argp.cmd == PROCTAL_CMD_SEARCH) {
		struct proctal_cmd_search_arg *arg = create_proctal_cmd_search_arg_from_yuck_arg(&argp);

		if (arg == NULL) {
			yuck_free(&argp);
			return 1;
		}

		exit_code = proctal_cmd_search(arg);

		destroy_proctal_cmd_search_arg_from_yuck_arg(arg);
	}

	yuck_free(&argp);
	return exit_code;
}

#include <stdio.h>
#include <stdlib.h>
#include <proctal.h>

#include "cmd.h"
#include "args.yucc"

static enum proctal_cmd_val_type yuck_arg_type_to_proctal_cmd_val_type(const char *arg)
{
	struct type {
		enum proctal_cmd_val_type type;
		const char *name;
	};

	static struct type types[] = {
		{
			.type = PROCTAL_CMD_VAL_TYPE_CHAR,
			.name = "char"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_UCHAR,
			.name = "uchar"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_SCHAR,
			.name = "schar"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_SHORT,
			.name = "short"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_USHORT,
			.name = "ushort"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_INT,
			.name = "int"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_UINT,
			.name = "uint"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_LONG,
			.name = "long"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_ULONG,
			.name = "ulong"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_LONGLONG,
			.name = "longlong"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_ULONGLONG,
			.name = "ulonglong"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_FLOAT,
			.name = "float"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_DOUBLE,
			.name = "double"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_LONGDOUBLE,
			.name = "longdouble"
		},
		{
			.type = PROCTAL_CMD_VAL_TYPE_ADDRESS,
			.name = "address"
		},
	};

	if (arg == NULL) {
		return PROCTAL_CMD_VAL_TYPE_UNKNOWN;
	}

	for (size_t i = 0; i < (sizeof types / sizeof types[0]); i++) {
		if (strcmp(types[i].name, arg) == 0) {
			return types[i].type;
		}
	}

	return PROCTAL_CMD_VAL_TYPE_UNKNOWN;
}

static struct proctal_cmd_read_arg *create_proctal_cmd_read_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct proctal_cmd_read_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_READ) {
		fputs("Wrong command.\n", stderr);
		free(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Wrong number of arguments.\n", stderr);
		free(arg);
		return NULL;
	}

	if (yuck_arg->read.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		free(arg);
		return NULL;
	}

	if (proctal_cmd_val_parse(yuck_arg->read.pid_arg, PROCTAL_CMD_VAL_TYPE_INT, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		free(arg);
		return NULL;
	}

	if (yuck_arg->read.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		free(arg);
		return NULL;
	}

	if (proctal_cmd_val_parse(yuck_arg->read.address_arg, PROCTAL_CMD_VAL_TYPE_ADDRESS, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		free(arg);
		return NULL;
	}

	arg->type = yuck_arg_type_to_proctal_cmd_val_type(yuck_arg->read.type_arg);

	if (arg->type == PROCTAL_CMD_VAL_TYPE_UNKNOWN) {
		arg->type = PROCTAL_CMD_VAL_TYPE_UCHAR;
	}

	return arg;
}

static void destroy_proctal_cmd_read_arg_from_yuck_arg(struct proctal_cmd_read_arg *arg)
{
	free(arg);
}

static struct proctal_cmd_write_arg *create_proctal_cmd_write_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct proctal_cmd_write_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_WRITE) {
		fputs("Wrong command.\n", stderr);
		free(arg);
		return NULL;
	}

	if (yuck_arg->nargs != 1) {
		fputs("Wrong number of arguments.\n", stderr);
		free(arg);
		return NULL;
	}

	if (yuck_arg->write.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		free(arg);
		return NULL;
	}

	if (proctal_cmd_val_parse(yuck_arg->write.pid_arg, PROCTAL_CMD_VAL_TYPE_INT, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		free(arg);
		return NULL;
	}

	if (yuck_arg->write.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		free(arg);
		return NULL;
	}

	if (proctal_cmd_val_parse(yuck_arg->write.address_arg, PROCTAL_CMD_VAL_TYPE_ADDRESS, &arg->address)) {
		fputs("Invalid address.\n", stderr);
		free(arg);
		return NULL;
	}

	arg->type = yuck_arg_type_to_proctal_cmd_val_type(yuck_arg->write.type_arg);

	if (arg->type == PROCTAL_CMD_VAL_TYPE_UNKNOWN) {
		arg->type = PROCTAL_CMD_VAL_TYPE_UCHAR;
	}

	arg->value = malloc(proctal_cmd_val_size(arg->type));
	if (proctal_cmd_val_parse(yuck_arg->args[0], arg->type, arg->value)) {
		fputs("Invalid value.\n", stderr);
		free(arg);
		return NULL;
	}

	return arg;
}

static void destroy_proctal_cmd_write_arg_from_yuck_arg(struct proctal_cmd_write_arg *arg)
{
	free(arg->value);
	free(arg);
}

static struct proctal_cmd_search_arg *create_proctal_cmd_search_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct proctal_cmd_search_arg *arg = malloc(sizeof *arg);

	if (yuck_arg->cmd != PROCTAL_CMD_SEARCH) {
		fputs("Wrong command.\n", stderr);
		free(arg);
		return NULL;
	}

	if (yuck_arg->search.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		free(arg);
		return NULL;
	}

	if (proctal_cmd_val_parse(yuck_arg->search.pid_arg, PROCTAL_CMD_VAL_TYPE_INT, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		free(arg);
		return NULL;
	}

	arg->type = yuck_arg_type_to_proctal_cmd_val_type(yuck_arg->search.type_arg);

	if (arg->type == PROCTAL_CMD_VAL_TYPE_UNKNOWN) {
		arg->type = PROCTAL_CMD_VAL_TYPE_UCHAR;
	}

	if (yuck_arg->search.input_flag) {
		arg->input = 1;
	}

#define GET_COMPARE_ARG(NAME) \
	if (yuck_arg->search.NAME##_arg != NULL) { \
		arg->NAME = 1; \
		arg->NAME##_value = malloc(proctal_cmd_val_size(arg->type)); \
		if (proctal_cmd_val_parse(yuck_arg->search.NAME##_arg, arg->type, arg->NAME##_value)) { \
			fputs("Invalid value for --NAME.\n", stderr); \
			free(arg); \
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
	GET_COMPARE_ARG(dec);

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

static void destroy_proctal_cmd_search_arg_from_yuck_arg(struct proctal_cmd_search_arg *arg)
{
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
	DESTROY_COMPARE_ARG(dec);

#undef DESTROY_COMPARE_ARG

	free(arg);
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

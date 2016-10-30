#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "proctal.h"
#include "command.h"
#include "args.yucc"

static int parse_zstr_char(const char *string, char *val)
{
	// TODO: figure out how to detect sign of char.
	int success = sscanf(string, "%hhd", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_schar(const char *string, signed char *val)
{
	int success = sscanf(string, "%hhd", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_uchar(const char *string, unsigned char *val)
{
	int success = sscanf(string, "%hhu", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_short(const char *string, short *val)
{
	int success = sscanf(string, "%hd", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_ushort(const char *string, unsigned short *val)
{
	int success = sscanf(string, "%hu", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_int(const char *string, int *val)
{
	int success = sscanf(string, "%d", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_uint(const char *string, unsigned int *val)
{
	int success = sscanf(string, "%u", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_long(const char *string, long *val)
{
	int success = sscanf(string, "%ld", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_ulong(const char *string, unsigned long *val)
{
	int success = sscanf(string, "%lu", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_longlong(const char *string, long long *val)
{
	int success = sscanf(string, "%lld", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_ulonglong(const char *string, unsigned long long *val)
{
	int success = sscanf(string, "%llu", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_float(const char *string, float *val)
{
	int success = sscanf(string, "%f", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_double(const char *string, double *val)
{
	int success = sscanf(string, "%lf", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_longdouble(const char *string, long double *val)
{
	int success = sscanf(string, "%Lf", val);

	return success == 1 ? 0 : -1;
}

static int parse_zstr_address(const char *string, void *addr)
{
	// TODO: figure out how to portably find address size.
	int success = sscanf(string, "%lx", (unsigned long *) addr);

	return success == 1 ? 0 : -1;
}

static int parse_value(enum proctal_command_value_type type, const char *string, void **value)
{
	// This fits for all types for now.
	*value = malloc(16);

	switch (type) {
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR:
		if (parse_zstr_char(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR:
		if (parse_zstr_uchar(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR:
		if (parse_zstr_schar(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT:
		if (parse_zstr_short(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT:
		if (parse_zstr_ushort(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_INT:
		if (parse_zstr_int(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_UINT:
		if (parse_zstr_uint(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONG:
		if (parse_zstr_long(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG:
		if (parse_zstr_ulong(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG:
		if (parse_zstr_longlong(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG:
		if (parse_zstr_ulonglong(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT:
		if (parse_zstr_float(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE:
		if (parse_zstr_double(string, *value)) {
			return -1;
		}
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE:
		if (parse_zstr_longdouble(string, *value)) {
			return -1;
		}
		break;
	default:
		return -1;
	}

	return 0;
}

static enum proctal_command_value_type yuck_arg_type_to_proctal_command_value_type(const char *arg)
{
	struct type {
		enum proctal_command_value_type type;
		const char *name;
	};

	static struct type types[] = {
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_CHAR,
			.name = "char"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_UCHAR,
			.name = "uchar"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_SCHAR,
			.name = "schar"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_SHORT,
			.name = "short"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_USHORT,
			.name = "ushort"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_INT,
			.name = "int"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_UINT,
			.name = "uint"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_LONG,
			.name = "long"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_ULONG,
			.name = "ulong"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_LONGLONG,
			.name = "longlong"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG,
			.name = "ulonglong"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_FLOAT,
			.name = "float"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_DOUBLE,
			.name = "double"
		},
		{
			.type = PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE,
			.name = "longdouble"
		},
	};

	if (arg == NULL) {
		return PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN;
	}

	for (int i = 0; i < (sizeof types / sizeof types[0]); i++) {
		if (strcmp(types[i].name, arg) == 0) {
			return types[i].type;
		}
	}

	return PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN;
}

static int yuck_arg_to_proctal_command_read_arg(yuck_t *yuck_arg, struct proctal_command_read_arg *proctal_command_arg)
{
	if (yuck_arg->cmd != PROCTAL_CMD_READ) {
		fputs("Wrong command.\n", stderr);
		return -1;
	}

	if (yuck_arg->nargs != 0) {
		fputs("Wrong number of arguments.\n", stderr);
		return -1;
	}

	if (yuck_arg->read.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		return -1;
	}

	if (parse_zstr_int(yuck_arg->read.pid_arg, &proctal_command_arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		return -1;
	}

	if (yuck_arg->read.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		return -1;
	}

	if (parse_zstr_address(yuck_arg->read.address_arg, &proctal_command_arg->address)) {
		fputs("Invalid address.\n", stderr);
		return -1;
	}

	proctal_command_arg->type = yuck_arg_type_to_proctal_command_value_type(yuck_arg->read.type_arg);

	if (proctal_command_arg->type == PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN) {
		proctal_command_arg->type = PROCTAL_COMMAND_VALUE_TYPE_UCHAR;
	}

	return 0;
}

static int yuck_arg_to_proctal_command_write_arg(yuck_t *yuck_arg, struct proctal_command_write_arg *proctal_command_arg)
{
	if (yuck_arg->cmd != PROCTAL_CMD_WRITE) {
		fputs("Wrong command.\n", stderr);
		return -1;
	}

	if (yuck_arg->nargs != 1) {
		fputs("Wrong number of arguments.\n", stderr);
		return -1;
	}

	if (yuck_arg->write.pid_arg == NULL) {
		fputs("OPTION -p, --pid is required.\n", stderr);
		return -1;
	}

	if (parse_zstr_int(yuck_arg->write.pid_arg, &proctal_command_arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		return -1;
	}

	if (yuck_arg->write.address_arg == NULL) {
		fputs("OPTION -a, --address is required.\n", stderr);
		return -1;
	}

	if (parse_zstr_address(yuck_arg->write.address_arg, &proctal_command_arg->address)) {
		fputs("Invalid address.\n", stderr);
		return -1;
	}

	proctal_command_arg->type = yuck_arg_type_to_proctal_command_value_type(yuck_arg->write.type_arg);

	if (proctal_command_arg->type == PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN) {
		proctal_command_arg->type = PROCTAL_COMMAND_VALUE_TYPE_UCHAR;
	}

	if (parse_value(proctal_command_arg->type, yuck_arg->args[0], &proctal_command_arg->value)) {
		fputs("Invalid value.\n", stderr);
		return -1;
	}

	return 0;
}

static struct proctal_command_search_arg *create_proctal_command_search_arg_from_yuck_arg(yuck_t *yuck_arg)
{
	struct proctal_command_search_arg *arg = malloc(sizeof *arg);

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

	if (parse_zstr_int(yuck_arg->search.pid_arg, &arg->pid)) {
		fputs("Invalid pid.\n", stderr);
		free(arg);
		return NULL;
	}

	arg->type = yuck_arg_type_to_proctal_command_value_type(yuck_arg->search.type_arg);

	if (arg->type == PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN) {
		arg->type = PROCTAL_COMMAND_VALUE_TYPE_UCHAR;
	}

#define GET_COMPARE_ARG(NAME) \
	if (yuck_arg->search.NAME##_arg != NULL) { \
		arg->NAME = 1; \
		if (parse_value(arg->type, yuck_arg->search.NAME##_arg, &arg->NAME##_value)) { \
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

static void destroy_proctal_command_search_arg_from_yuck_arg(struct proctal_command_search_arg *arg)
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
		goto bad_parse;
	}

	if (argp.help_flag) {
		yuck_auto_help(&argp);
	} else if (argp.version_flag) {
		yuck_auto_version(&argp);
	} else if (argp.cmd == YUCK_NOCMD) {
		yuck_auto_help(&argp);
	} else if (argp.cmd == PROCTAL_CMD_WRITE) {
		struct proctal_command_write_arg arg;

		if (yuck_arg_to_proctal_command_write_arg(&argp, &arg) != 0) {
			goto bad_parse;
		}

		proctal_command_write(&arg);
	} else if (argp.cmd == PROCTAL_CMD_READ) {
		struct proctal_command_read_arg arg;

		if (yuck_arg_to_proctal_command_read_arg(&argp, &arg) != 0) {
			goto bad_parse;
		}

		proctal_command_read(&arg);
	} else if (argp.cmd == PROCTAL_CMD_SEARCH) {
		struct proctal_command_search_arg *arg = create_proctal_command_search_arg_from_yuck_arg(&argp);

		if (arg == NULL) {
			goto bad_parse;
		}

		proctal_command_search(arg);

		destroy_proctal_command_search_arg_from_yuck_arg(arg);
	}

	yuck_free(&argp);

	return 0;

bad_parse:
	yuck_free(&argp);

	return 1;
}

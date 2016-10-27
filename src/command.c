#include <stdio.h>
#include <sys/uio.h>

#include "proctal.h"
#include "command.h"

void proctal_command_read(struct proctal_command_read_arg *arg)
{
#define ERROR_CHECKER(CALL) \
	if (CALL != 0) { \
		goto fail; \
	}

	switch (arg->type) {
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR: {
		char val;

		ERROR_CHECKER(proctal_read_char(arg->pid, arg->address, &val));

		printf("%d\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR: {
		unsigned char val;

		ERROR_CHECKER(proctal_read_uchar(arg->pid, arg->address, &val));

		printf("%u\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR: {
		signed char val;

		ERROR_CHECKER(proctal_read_schar(arg->pid, arg->address, &val));

		printf("%d\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT: {
		short val;

		ERROR_CHECKER(proctal_read_short(arg->pid, arg->address, &val));

		printf("%d\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT: {
		unsigned short val;

		ERROR_CHECKER(proctal_read_ushort(arg->pid, arg->address, &val));

		printf("%u\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_INT: {
		int val;

		ERROR_CHECKER(proctal_read_int(arg->pid, arg->address, &val));

		printf("%d\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_UINT: {
		unsigned int val;

		ERROR_CHECKER(proctal_read_uint(arg->pid, arg->address, &val));

		printf("%u\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_LONG: {
		long val;

		ERROR_CHECKER(proctal_read_long(arg->pid, arg->address, &val));

		printf("%ld\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG: {
		unsigned long val;

		ERROR_CHECKER(proctal_read_ulong(arg->pid, arg->address, &val));

		printf("%lu\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG: {
		long long val;

		ERROR_CHECKER(proctal_read_longlong(arg->pid, arg->address, &val));

		printf("%lld\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG: {
		unsigned long long val;

		ERROR_CHECKER(proctal_read_ulonglong(arg->pid, arg->address, &val));

		printf("%llu\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT: {
		float val;

		ERROR_CHECKER(proctal_read_float(arg->pid, arg->address, &val));

		printf("%f\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE: {
		double val;

		ERROR_CHECKER(proctal_read_double(arg->pid, arg->address, &val));

		printf("%f\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE: {
		long double val;

		ERROR_CHECKER(proctal_read_longdouble(arg->pid, arg->address, &val));

		printf("%Lf\n", val);
		break;
	}
	default:
		goto fail;
	}

#undef ERROR_CHECKER

	return;

fail:
	fprintf(stderr, "Failed to read memory.\n");
}

void proctal_command_write(struct proctal_command_write_arg *arg)
{
#define ERROR_CHECKER(CALL) \
	if (CALL != 0) { \
		goto fail; \
	}

	switch (arg->type) {
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR:
		ERROR_CHECKER(proctal_write_char(arg->pid, arg->address, *((char *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR:
		ERROR_CHECKER(proctal_write_uchar(arg->pid, arg->address, *((unsigned char *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR:
		ERROR_CHECKER(proctal_write_schar(arg->pid, arg->address, *((signed char *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT:
		ERROR_CHECKER(proctal_write_short(arg->pid, arg->address, *((short *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT:
		ERROR_CHECKER(proctal_write_ushort(arg->pid, arg->address, *((unsigned short *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_INT:
		ERROR_CHECKER(proctal_write_int(arg->pid, arg->address, *((int *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_UINT:
		ERROR_CHECKER(proctal_write_uint(arg->pid, arg->address, *((unsigned int *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONG:
		ERROR_CHECKER(proctal_write_long(arg->pid, arg->address, *((long *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG:
		ERROR_CHECKER(proctal_write_ulong(arg->pid, arg->address, *((unsigned long *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG:
		ERROR_CHECKER(proctal_write_longlong(arg->pid, arg->address, *((long long *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG:
		ERROR_CHECKER(proctal_write_ulonglong(arg->pid, arg->address, *((unsigned long long *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT:
		ERROR_CHECKER(proctal_write_float(arg->pid, arg->address, *((float *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE:
		ERROR_CHECKER(proctal_write_double(arg->pid, arg->address, *((double *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE:
		ERROR_CHECKER(proctal_write_longdouble(arg->pid, arg->address, *((long double *) arg->value)));
		break;
	default:
		goto fail;
	}

	return;

#undef ERROR_CHECKER

fail:
	fprintf(stderr, "Failed to write to memory.\n");
}

void proctal_command_search(struct proctal_command_search_arg *arg)
{
	proctal_search_state state = proctal_search_state_create();
	proctal_search_options options = proctal_search_options_create();
	void *addr;
	char value[20];

	while (proctal_search(arg->pid, state, options, &addr, (void *) &value) == 1) {
		printf("%p %d\n", addr, (int) *value);
	}

	proctal_search_state_delete(state);
	proctal_search_options_delete(options);
}

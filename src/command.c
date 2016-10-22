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
	switch (proctal_write_int(arg->pid, arg->address, arg->value)) {
	case 0:
		break;
	default:
		fprintf(stderr, "Failed to write to memory.\n");
	}
}

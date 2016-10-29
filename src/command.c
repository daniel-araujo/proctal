#include <stdlib.h>
#include <stdio.h>
#include <sys/uio.h>

#include "proctal.h"
#include "command.h"

void proctal_command_read(struct proctal_command_read_arg *arg)
{
	proctal p = proctal_create();
	proctal_set_pid(p, arg->pid);

	if (p == NULL) {
		goto fail;
	}

#define ERROR_CHECKER(CALL) \
	if (CALL != 0) { \
		goto fail; \
	}

	switch (arg->type) {
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR: {
		char val;

		ERROR_CHECKER(proctal_read_char(p, arg->address, &val));

		printf("%d\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR: {
		unsigned char val;

		ERROR_CHECKER(proctal_read_uchar(p, arg->address, &val));

		printf("%u\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR: {
		signed char val;

		ERROR_CHECKER(proctal_read_schar(p, arg->address, &val));

		printf("%d\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT: {
		short val;

		ERROR_CHECKER(proctal_read_short(p, arg->address, &val));

		printf("%d\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT: {
		unsigned short val;

		ERROR_CHECKER(proctal_read_ushort(p, arg->address, &val));

		printf("%u\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_INT: {
		int val;

		ERROR_CHECKER(proctal_read_int(p, arg->address, &val));

		printf("%d\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_UINT: {
		unsigned int val;

		ERROR_CHECKER(proctal_read_uint(p, arg->address, &val));

		printf("%u\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_LONG: {
		long val;

		ERROR_CHECKER(proctal_read_long(p, arg->address, &val));

		printf("%ld\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG: {
		unsigned long val;

		ERROR_CHECKER(proctal_read_ulong(p, arg->address, &val));

		printf("%lu\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG: {
		long long val;

		ERROR_CHECKER(proctal_read_longlong(p, arg->address, &val));

		printf("%lld\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG: {
		unsigned long long val;

		ERROR_CHECKER(proctal_read_ulonglong(p, arg->address, &val));

		printf("%llu\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT: {
		float val;

		ERROR_CHECKER(proctal_read_float(p, arg->address, &val));

		printf("%f\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE: {
		double val;

		ERROR_CHECKER(proctal_read_double(p, arg->address, &val));

		printf("%f\n", val);
		break;
	}
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE: {
		long double val;

		ERROR_CHECKER(proctal_read_longdouble(p, arg->address, &val));

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
	proctal p = proctal_create();
	proctal_set_pid(p, arg->pid);

	if (p == NULL) {
		goto fail;
	}

#define ERROR_CHECKER(CALL) \
	if (CALL != 0) { \
		goto fail; \
	}

	switch (arg->type) {
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR:
		ERROR_CHECKER(proctal_write_char(p, arg->address, *((char *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR:
		ERROR_CHECKER(proctal_write_uchar(p, arg->address, *((unsigned char *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR:
		ERROR_CHECKER(proctal_write_schar(p, arg->address, *((signed char *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT:
		ERROR_CHECKER(proctal_write_short(p, arg->address, *((short *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT:
		ERROR_CHECKER(proctal_write_ushort(p, arg->address, *((unsigned short *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_INT:
		ERROR_CHECKER(proctal_write_int(p, arg->address, *((int *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_UINT:
		ERROR_CHECKER(proctal_write_uint(p, arg->address, *((unsigned int *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONG:
		ERROR_CHECKER(proctal_write_long(p, arg->address, *((long *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG:
		ERROR_CHECKER(proctal_write_ulong(p, arg->address, *((unsigned long *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG:
		ERROR_CHECKER(proctal_write_longlong(p, arg->address, *((long long *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG:
		ERROR_CHECKER(proctal_write_ulonglong(p, arg->address, *((unsigned long long *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT:
		ERROR_CHECKER(proctal_write_float(p, arg->address, *((float *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE:
		ERROR_CHECKER(proctal_write_double(p, arg->address, *((double *) arg->value)));
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE:
		ERROR_CHECKER(proctal_write_longdouble(p, arg->address, *((long double *) arg->value)));
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
	proctal p = proctal_create();
	proctal_set_pid(p, arg->pid);

	proctal_addr_iter iter = proctal_addr_iter_create(p);
	proctal_addr_iter_set_align(iter, sizeof (int));
	proctal_addr_iter_set_size(iter, sizeof (int));

	void *addr;
	while (proctal_addr_iter_next(iter, &addr) == 0) {
		int i;
		proctal_read_int(p, addr, &i);
		printf("%p %d\n", addr, i);
	}

	proctal_addr_iter_destroy(iter);
}

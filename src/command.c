#include <stdlib.h>
#include <stdio.h>
#include <sys/uio.h>
#include <stdalign.h>

#include "proctal.h"
#include "command.h"

static inline size_t value_type_align(enum proctal_command_value_type type)
{
	switch (type) {
	default:
	case PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN:
		return alignof(char);
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR:
		return alignof(char);
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR:
		return alignof(unsigned char);
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR:
		return alignof(signed char);
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT:
		return alignof(short);
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT:
		return alignof(unsigned short);
	case PROCTAL_COMMAND_VALUE_TYPE_INT:
		return alignof(int);
	case PROCTAL_COMMAND_VALUE_TYPE_UINT:
		return alignof(unsigned int);
	case PROCTAL_COMMAND_VALUE_TYPE_LONG:
		return alignof(long);
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG:
		return alignof(unsigned long);
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG:
		return alignof(long long);
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG:
		return alignof(unsigned long long);
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT:
		return alignof(float);
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE:
		return alignof(double);
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE:
		return alignof(long double);
	}
}

static inline size_t value_type_size(enum proctal_command_value_type type)
{
	switch (type) {
	default:
	case PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN:
		return sizeof(char);
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR:
		return sizeof(char);
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR:
		return sizeof(unsigned char);
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR:
		return sizeof(signed char);
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT:
		return sizeof(short);
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT:
		return sizeof(unsigned short);
	case PROCTAL_COMMAND_VALUE_TYPE_INT:
		return sizeof(int);
	case PROCTAL_COMMAND_VALUE_TYPE_UINT:
		return sizeof(unsigned int);
	case PROCTAL_COMMAND_VALUE_TYPE_LONG:
		return sizeof(long);
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG:
		return sizeof(unsigned long);
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG:
		return sizeof(long long);
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG:
		return sizeof(unsigned long long);
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT:
		return sizeof(float);
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE:
		return sizeof(double);
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE:
		return sizeof(long double);
	}
}

static inline int value_type_cmp(enum proctal_command_value_type type, void *v1, void *v2)
{
#define DEREFERENCE(TYPE) \
	(*(TYPE*) v1 == *(TYPE*) v2 ? 0 : (*(TYPE*) v1 > *(TYPE*) v2 ? 1 : -1))

	switch (type) {
	default:
	case PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN:
		return DEREFERENCE(char);
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR:
		return DEREFERENCE(char);
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR:
		return DEREFERENCE(unsigned char);
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR:
		return DEREFERENCE(signed char);
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT:
		return DEREFERENCE(short);
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT:
		return DEREFERENCE(unsigned short);
	case PROCTAL_COMMAND_VALUE_TYPE_INT:
		return DEREFERENCE(int);
	case PROCTAL_COMMAND_VALUE_TYPE_UINT:
		return DEREFERENCE(unsigned int);
	case PROCTAL_COMMAND_VALUE_TYPE_LONG:
		return DEREFERENCE(long);
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG:
		return DEREFERENCE(unsigned long);
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG:
		return DEREFERENCE(long long);
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG:
		return DEREFERENCE(unsigned long long);
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT:
		return DEREFERENCE(float);
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE:
		return DEREFERENCE(double);
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE:
		return DEREFERENCE(long double);
	}
}

static inline void print_address(void *addr)
{
	printf("%p", addr);
}

static inline void print_value_type(enum proctal_command_value_type type, void *value)
{
	switch (type) {
	default:
	case PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN:
		printf("?");
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_CHAR:
		printf("%d", *(char *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_UCHAR:
		printf("%u", *(unsigned char *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_SCHAR:
		printf("%d", *(signed char *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_SHORT:
		printf("%d", *(short *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_USHORT:
		printf("%u", *(unsigned short *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_INT:
		printf("%d", *(int *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_UINT:
		printf("%u", *(unsigned int *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONG:
		printf("%ld", *(long *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_ULONG:
		printf("%lu", *(unsigned long *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONGLONG:
		printf("%lld", *(long long *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG:
		printf("%llu", *(unsigned long long *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_FLOAT:
		printf("%f", *(float *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_DOUBLE:
		printf("%f", *(double *) value);
		break;
	case PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE:
		printf("%Lf", *(long double *) value);
		break;
	}
}

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

	proctal_destroy(p);
	return;

fail:
	proctal_destroy(p);
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

	proctal_destroy(p);
	return;

#undef ERROR_CHECKER

fail:
	proctal_destroy(p);
	fprintf(stderr, "Failed to write to memory.\n");
}

void proctal_command_search(struct proctal_command_search_arg *arg)
{
	size_t size = value_type_size(arg->type);

	proctal p = proctal_create();
	proctal_set_pid(p, arg->pid);

	proctal_addr_iter iter = proctal_addr_iter_create(p);
	proctal_addr_iter_set_align(iter, value_type_align(arg->type));
	proctal_addr_iter_set_size(iter, size);

	void *addr;
	void *value = malloc(20);
	while (proctal_addr_iter_next(iter, &addr) == 0) {
		proctal_read(p, addr, value, size);

		if (arg->eq && value_type_cmp(arg->type, value, arg->eq_value) != 0) {
			continue;
		}

		if (arg->gt && value_type_cmp(arg->type, value, arg->gt_value) != 1) {
			continue;
		}

		if (arg->gte && value_type_cmp(arg->type, value, arg->gte_value) < 0) {
			continue;
		}

		if (arg->lt && value_type_cmp(arg->type, value, arg->lt_value) != -1) {
			continue;
		}

		if (arg->lte && value_type_cmp(arg->type, value, arg->lte_value) > 0) {
			continue;
		}

		if (arg->ne && value_type_cmp(arg->type, value, arg->ne_value) == 0) {
			continue;
		}

		print_address(addr);
		printf(" ");
		print_value_type(arg->type, value);
		printf("\n");
	}
	free(value);

	proctal_addr_iter_destroy(iter);
	proctal_destroy(p);
}

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
	printf("%lx", (unsigned long) addr);
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

int proctal_command_read(struct proctal_command_read_arg *arg)
{
	proctal p = proctal_create();

	if (p == NULL) {
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	size_t size = value_type_size(arg->type);
	void *value = malloc(size);

	if (proctal_read(p, arg->address, value, size) != 0) { \
		fprintf(stderr, "Failed to read memory.\n");
		proctal_destroy(p);
		return 1;
	}

	print_value_type(arg->type, value);
	printf("\n");

	free(value);

	proctal_destroy(p);

	return 0;
}

int proctal_command_write(struct proctal_command_write_arg *arg)
{
	proctal p = proctal_create();

	if (p == NULL) {
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	size_t size = value_type_size(arg->type);

	if (proctal_write(p, arg->address, arg->value, size) != 0) {
		fprintf(stderr, "Failed to write to memory.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_destroy(p);

	return 0;
}

int proctal_command_search(struct proctal_command_search_arg *arg)
{
	proctal p = proctal_create();

	if (p == NULL) {
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	size_t size = value_type_size(arg->type);

	proctal_addr_iter iter = proctal_addr_iter_create(p);
	proctal_addr_iter_set_align(iter, value_type_align(arg->type));
	proctal_addr_iter_set_size(iter, size);

	void *addr;
	void *value = malloc(size);

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

	return 0;
}

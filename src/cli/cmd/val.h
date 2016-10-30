#ifndef CMD_VAL_H
#define CMD_VAL_H

#include <stdio.h>
#include <stdalign.h>

enum proctal_cmd_val_type {
	PROCTAL_CMD_VAL_TYPE_UNKNOWN,
	PROCTAL_CMD_VAL_TYPE_CHAR,
	PROCTAL_CMD_VAL_TYPE_UCHAR,
	PROCTAL_CMD_VAL_TYPE_SCHAR,
	PROCTAL_CMD_VAL_TYPE_SHORT,
	PROCTAL_CMD_VAL_TYPE_USHORT,
	PROCTAL_CMD_VAL_TYPE_INT,
	PROCTAL_CMD_VAL_TYPE_UINT,
	PROCTAL_CMD_VAL_TYPE_LONG,
	PROCTAL_CMD_VAL_TYPE_ULONG,
	PROCTAL_CMD_VAL_TYPE_LONGLONG,
	PROCTAL_CMD_VAL_TYPE_ULONGLONG,
	PROCTAL_CMD_VAL_TYPE_FLOAT,
	PROCTAL_CMD_VAL_TYPE_DOUBLE,
	PROCTAL_CMD_VAL_TYPE_LONGDOUBLE,
	PROCTAL_CMD_VAL_TYPE_ADDRESS,
};

inline size_t proctal_cmd_val_align(enum proctal_cmd_val_type type)
{
	switch (type) {
	default:
	case PROCTAL_CMD_VAL_TYPE_UNKNOWN:
		return alignof(char);
	case PROCTAL_CMD_VAL_TYPE_CHAR:
		return alignof(char);
	case PROCTAL_CMD_VAL_TYPE_UCHAR:
		return alignof(unsigned char);
	case PROCTAL_CMD_VAL_TYPE_SCHAR:
		return alignof(signed char);
	case PROCTAL_CMD_VAL_TYPE_SHORT:
		return alignof(short);
	case PROCTAL_CMD_VAL_TYPE_USHORT:
		return alignof(unsigned short);
	case PROCTAL_CMD_VAL_TYPE_INT:
		return alignof(int);
	case PROCTAL_CMD_VAL_TYPE_UINT:
		return alignof(unsigned int);
	case PROCTAL_CMD_VAL_TYPE_LONG:
		return alignof(long);
	case PROCTAL_CMD_VAL_TYPE_ULONG:
		return alignof(unsigned long);
	case PROCTAL_CMD_VAL_TYPE_LONGLONG:
		return alignof(long long);
	case PROCTAL_CMD_VAL_TYPE_ULONGLONG:
		return alignof(unsigned long long);
	case PROCTAL_CMD_VAL_TYPE_FLOAT:
		return alignof(float);
	case PROCTAL_CMD_VAL_TYPE_DOUBLE:
		return alignof(double);
	case PROCTAL_CMD_VAL_TYPE_LONGDOUBLE:
		return alignof(long double);
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return alignof(void *);
	}
}

inline size_t proctal_cmd_val_size(enum proctal_cmd_val_type type)
{
	switch (type) {
	default:
	case PROCTAL_CMD_VAL_TYPE_UNKNOWN:
		return sizeof(char);
	case PROCTAL_CMD_VAL_TYPE_CHAR:
		return sizeof(char);
	case PROCTAL_CMD_VAL_TYPE_UCHAR:
		return sizeof(unsigned char);
	case PROCTAL_CMD_VAL_TYPE_SCHAR:
		return sizeof(signed char);
	case PROCTAL_CMD_VAL_TYPE_SHORT:
		return sizeof(short);
	case PROCTAL_CMD_VAL_TYPE_USHORT:
		return sizeof(unsigned short);
	case PROCTAL_CMD_VAL_TYPE_INT:
		return sizeof(int);
	case PROCTAL_CMD_VAL_TYPE_UINT:
		return sizeof(unsigned int);
	case PROCTAL_CMD_VAL_TYPE_LONG:
		return sizeof(long);
	case PROCTAL_CMD_VAL_TYPE_ULONG:
		return sizeof(unsigned long);
	case PROCTAL_CMD_VAL_TYPE_LONGLONG:
		return sizeof(long long);
	case PROCTAL_CMD_VAL_TYPE_ULONGLONG:
		return sizeof(unsigned long long);
	case PROCTAL_CMD_VAL_TYPE_FLOAT:
		return sizeof(float);
	case PROCTAL_CMD_VAL_TYPE_DOUBLE:
		return sizeof(double);
	case PROCTAL_CMD_VAL_TYPE_LONGDOUBLE:
		return sizeof(long double);
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return sizeof(void *);
	}
}

inline int proctal_cmd_val_cmp(enum proctal_cmd_val_type type, void *v1, void *v2)
{
#define DEREFERENCE(TYPE) \
	(*(TYPE*) v1 == *(TYPE*) v2 ? 0 : (*(TYPE*) v1 > *(TYPE*) v2 ? 1 : -1))

	switch (type) {
	default:
	case PROCTAL_CMD_VAL_TYPE_UNKNOWN:
		return DEREFERENCE(char);
	case PROCTAL_CMD_VAL_TYPE_CHAR:
		return DEREFERENCE(char);
	case PROCTAL_CMD_VAL_TYPE_UCHAR:
		return DEREFERENCE(unsigned char);
	case PROCTAL_CMD_VAL_TYPE_SCHAR:
		return DEREFERENCE(signed char);
	case PROCTAL_CMD_VAL_TYPE_SHORT:
		return DEREFERENCE(short);
	case PROCTAL_CMD_VAL_TYPE_USHORT:
		return DEREFERENCE(unsigned short);
	case PROCTAL_CMD_VAL_TYPE_INT:
		return DEREFERENCE(int);
	case PROCTAL_CMD_VAL_TYPE_UINT:
		return DEREFERENCE(unsigned int);
	case PROCTAL_CMD_VAL_TYPE_LONG:
		return DEREFERENCE(long);
	case PROCTAL_CMD_VAL_TYPE_ULONG:
		return DEREFERENCE(unsigned long);
	case PROCTAL_CMD_VAL_TYPE_LONGLONG:
		return DEREFERENCE(long long);
	case PROCTAL_CMD_VAL_TYPE_ULONGLONG:
		return DEREFERENCE(unsigned long long);
	case PROCTAL_CMD_VAL_TYPE_FLOAT:
		return DEREFERENCE(float);
	case PROCTAL_CMD_VAL_TYPE_DOUBLE:
		return DEREFERENCE(double);
	case PROCTAL_CMD_VAL_TYPE_LONGDOUBLE:
		return DEREFERENCE(long double);
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return DEREFERENCE(void *);
	}

#undef DEREFERENCE
}

inline void proctal_cmd_val_print(FILE *f, enum proctal_cmd_val_type type, void *value)
{
	switch (type) {
	default:
	case PROCTAL_CMD_VAL_TYPE_UNKNOWN:
		fprintf(f, "?");
		break;
	case PROCTAL_CMD_VAL_TYPE_CHAR:
		fprintf(f, "%d", *(char *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_UCHAR:
		fprintf(f, "%u", *(unsigned char *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_SCHAR:
		fprintf(f, "%d", *(signed char *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_SHORT:
		fprintf(f, "%d", *(short *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_USHORT:
		fprintf(f, "%u", *(unsigned short *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_INT:
		fprintf(f, "%d", *(int *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_UINT:
		fprintf(f, "%u", *(unsigned int *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_LONG:
		fprintf(f, "%ld", *(long *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_ULONG:
		fprintf(f, "%lu", *(unsigned long *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_LONGLONG:
		fprintf(f, "%lld", *(long long *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_ULONGLONG:
		fprintf(f, "%llu", *(unsigned long long *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_FLOAT:
		fprintf(f, "%f", *(float *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_DOUBLE:
		fprintf(f, "%f", *(double *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_LONGDOUBLE:
		fprintf(f, "%Lf", *(long double *) value);
		break;
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		fprintf(f, "%lx", *(unsigned long *) value);
		break;
	}
}

inline int proctal_cmd_val_scan(FILE *f, enum proctal_cmd_val_type type, void *value)
{
	switch (type) {
	case PROCTAL_CMD_VAL_TYPE_CHAR: {
		// TODO: figure out how to detect sign of char.
		int success = fscanf(f, "%hhd", (char *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_SCHAR: {
		int success = fscanf(f, "%hhd", (signed char *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_UCHAR: {
		int success = fscanf(f, "%hhu", (unsigned char *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_SHORT: {
		int success = fscanf(f, "%hd", (short *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_USHORT: {
		int success = fscanf(f, "%hu", (unsigned short *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_INT: {
		int success = fscanf(f, "%d", (int *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_UINT: {
		int success = fscanf(f, "%u", (unsigned int *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_LONG: {
		int success = fscanf(f, "%ld", (long *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_ULONG: {
		int success = fscanf(f, "%lu", (unsigned long *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_LONGLONG: {
		int success = fscanf(f, "%lld", (long long *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_ULONGLONG: {
		int success = fscanf(f, "%llu", (unsigned long long *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_FLOAT: {
		int success = fscanf(f, "%f", (float *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_DOUBLE: {
		int success = fscanf(f, "%lf", (double *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_LONGDOUBLE: {
		int success = fscanf(f, "%Lf", (long double *) value);
		return success == 1 ? 1 : 0;
	}
	case PROCTAL_CMD_VAL_TYPE_ADDRESS: {
		int success = fscanf(f, "%lx", (unsigned long *) value);
		return success == 1 ? 1 : 0;
	}
	default:
		return 0;
	}
}

inline int proctal_cmd_val_parse(const char *s, enum proctal_cmd_val_type type, void *val)
{
	switch (type) {
	case PROCTAL_CMD_VAL_TYPE_CHAR:
		// TODO: figure out how to detect sign of char.
		if (sscanf(s, "%hhd", (char *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_UCHAR:
		if (sscanf(s, "%hhd", (unsigned char *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_SCHAR:
		if (sscanf(s, "%hhu", (signed char *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_SHORT:
		if (sscanf(s, "%hd", (short *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_USHORT:
		if (sscanf(s, "%hu", (unsigned short *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_INT:
		if (sscanf(s, "%d", (int *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_UINT:
		if (sscanf(s, "%u", (unsigned int *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_LONG:
		if (sscanf(s, "%ld", (long *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_ULONG:
		if (sscanf(s, "%lu", (unsigned long *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_LONGLONG:
		if (sscanf(s, "%lld", (long long *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_ULONGLONG:
		if (sscanf(s, "%llu", (unsigned long long *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_FLOAT:
		if (sscanf(s, "%f", (float *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_DOUBLE:
		if (sscanf(s, "%lf", (double *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_LONGDOUBLE:
		if (sscanf(s, "%Lf", (long double *) val) != 1) {
			return -1;
		}
		break;
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		// TODO: figure out how to portably find address format string.
		if (sscanf(s, "%lx", (unsigned long *) val) != 1) {
			return -1;
		}
		break;
	default:
		return -1;
	}

	return 0;
}

#endif /* CMD_VAL_H */

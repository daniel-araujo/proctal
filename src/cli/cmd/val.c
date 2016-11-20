#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "cmd/val.h"

struct proctal_cmd_val_attr_ieee754 {
	enum proctal_cmd_val_type_ieee754_precision precision;
};

struct proctal_cmd_val_attr_text {
	enum proctal_cmd_val_type_text_charset charset;
};

struct proctal_cmd_val_attr_integer {
	enum proctal_cmd_val_type_integer_size size;
	enum proctal_cmd_val_type_integer_sign sign;
};

struct proctal_cmd_val_attr {
	enum proctal_cmd_val_type type;
	void *type_attr;
	enum proctal_cmd_val_type_endianness endianness;
};

struct proctal_cmd_val_str {
	size_t size;
	char *data;
};

struct proctal_cmd_val_ins {
	void *addr;
	cs_insn *insn;
};

struct proctal_cmd_val {
	struct proctal_cmd_val_attr attr;
	void *value;
};

proctal_cmd_val_attr proctal_cmd_val_attr_create(enum proctal_cmd_val_type type)
{
	proctal_cmd_val_attr a = (proctal_cmd_val_attr) malloc(sizeof *a);

	if (a == NULL) {
		return NULL;
	}

	a->type = type;
	a->type_attr = NULL;
	a->endianness = PROCTAL_CMD_VAL_TYPE_ENDIANNESS_LITTLE;

	switch (a->type) {
	case PROCTAL_CMD_VAL_TYPE_INTEGER: {
		struct proctal_cmd_val_attr_integer *ta = (struct proctal_cmd_val_attr_integer *) malloc(sizeof *ta);

		if (ta == NULL) {
			free(a);
			return NULL;
		}

		ta->size = PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8;
		ta->sign = PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_2SCMPL;

		a->type_attr = ta;
		break;
	}
	case PROCTAL_CMD_VAL_TYPE_IEEE754: {
		struct proctal_cmd_val_attr_ieee754 *ta = (struct proctal_cmd_val_attr_ieee754 *) malloc(sizeof *ta);

		if (ta == NULL) {
			free(a);
			return NULL;
		}

		ta->precision = PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE;

		a->type_attr = ta;
		break;
	}
	case PROCTAL_CMD_VAL_TYPE_TEXT: {
		struct proctal_cmd_val_attr_text *ta = (struct proctal_cmd_val_attr_text *) malloc(sizeof *ta);

		if (ta == NULL) {
			free(a);
			return NULL;
		}

		ta->charset = PROCTAL_CMD_VAL_TYPE_TEXT_CHARSET_ASCII;

		a->type_attr = ta;
		break;
	}
	}

	return a;
}

void proctal_cmd_val_attr_destroy(proctal_cmd_val_attr a)
{
	if (a->type_attr) {
		free(a->type_attr);
	}

	free(a);
}

void proctal_cmd_val_attr_set_endianness(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_endianness endianness)
{
	a->endianness = endianness;
}

void proctal_cmd_val_attr_set_integer_size(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_integer_size size)
{
	if (a->type != PROCTAL_CMD_VAL_TYPE_INTEGER) {
		return;
	}

	((struct proctal_cmd_val_attr_integer *) a->type_attr)->size = size;
}

void proctal_cmd_val_attr_set_integer_sign(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_integer_sign sign)
{
	if (a->type != PROCTAL_CMD_VAL_TYPE_INTEGER) {
		return;
	}

	((struct proctal_cmd_val_attr_integer *) a->type_attr)->sign = sign;
}

void proctal_cmd_val_attr_set_ieee754_precision(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_ieee754_precision precision)
{
	if (a->type != PROCTAL_CMD_VAL_TYPE_IEEE754) {
		return;
	}

	((struct proctal_cmd_val_attr_ieee754 *) a->type_attr)->precision = precision;
}

void proctal_cmd_val_attr_set_text_charset(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_text_charset charset)
{
	if (a->type != PROCTAL_CMD_VAL_TYPE_TEXT) {
		return;
	}

	((struct proctal_cmd_val_attr_text *) a->type_attr)->charset = charset;
}

void proctal_cmd_val_destroy(proctal_cmd_val v)
{
	switch (v->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
	case PROCTAL_CMD_VAL_TYPE_INTEGER:
	case PROCTAL_CMD_VAL_TYPE_IEEE754:
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		if (v->value) {
			free(v->value);
		}
		break;

	case PROCTAL_CMD_VAL_TYPE_INSTRUCTION: {
		struct proctal_cmd_val_ins *value = (struct proctal_cmd_val_ins *) v->value;

		if (value->insn) {
			cs_free(value->insn, 1);
		}

		free(v->value);
		break;
	}

	case PROCTAL_CMD_VAL_TYPE_TEXT: {
		if (v->value == NULL) {
			break;
		}

		struct proctal_cmd_val_str *value = (struct proctal_cmd_val_str *) v->value;

		if (value->data) {
			free(value->data);
		}

		free(v->value);
		break;
	}
	}

	if (v->attr.type_attr) {
		free(v->attr.type_attr);
	}

	free(v);
}

proctal_cmd_val proctal_cmd_val_create(proctal_cmd_val_attr a)
{
	proctal_cmd_val v = (proctal_cmd_val) malloc(sizeof *v);

	if (v == NULL) {
		return NULL;
	}

	v->attr.type = a->type;
	v->attr.type_attr = NULL;
	v->value = NULL;

#define COPY_TYPE_ATTR(TYPE) \
	do { \
		TYPE *ta = (TYPE *) a->type_attr; \
		TYPE *ta2 = (TYPE *) malloc(sizeof *ta); \
		if (ta2 == NULL) { \
			proctal_cmd_val_destroy(v); \
			return NULL; \
		} \
		*ta2 = *ta; \
		v->attr.type_attr = ta2; \
	} while (0)

	switch (a->type) {
	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		COPY_TYPE_ATTR(struct proctal_cmd_val_attr_integer);
		break;

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		COPY_TYPE_ATTR(struct proctal_cmd_val_attr_ieee754);
		break;

	case PROCTAL_CMD_VAL_TYPE_TEXT:
		COPY_TYPE_ATTR(struct proctal_cmd_val_attr_text);
		break;
	}

#undef COPY_TYPE_ATTR

	switch (v->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
	case PROCTAL_CMD_VAL_TYPE_INTEGER:
	case PROCTAL_CMD_VAL_TYPE_IEEE754:
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		v->value = malloc(proctal_cmd_val_sizeof(v));

		if (v->value == NULL) {
			proctal_cmd_val_destroy(v);
			return NULL;
		}
		break;

	case PROCTAL_CMD_VAL_TYPE_TEXT:
		if (((struct proctal_cmd_val_attr_text *) v->attr.type_attr)->charset == PROCTAL_CMD_VAL_TYPE_TEXT_CHARSET_ASCII) {
			struct proctal_cmd_val_str *value = malloc(sizeof *value);

			if (value == NULL) {
				proctal_cmd_val_destroy(v);
				return NULL;
			}

			value->size = 1;
			value->data = (char *) malloc(value->size);

			if (value->data == NULL) {
				proctal_cmd_val_destroy(v);
				return NULL;
			}

			v->value = value;
		}
		break;

	case PROCTAL_CMD_VAL_TYPE_INSTRUCTION: {
		struct proctal_cmd_val_ins *value = malloc(sizeof *value);

		if (value == NULL) {
			proctal_cmd_val_destroy(v);
			return NULL;
		}

		value->insn = NULL;

		v->value = value;
		break;
	}

	default:
		proctal_cmd_val_destroy(v);
		return NULL;
	}

	return v;
}

void proctal_cmd_val_set_instruction_addr(proctal_cmd_val v, void *addr)
{
	if (v->attr.type != PROCTAL_CMD_VAL_TYPE_INSTRUCTION) {
		return;
	}

	struct proctal_cmd_val_ins *value = (struct proctal_cmd_val_ins *) v->value;

	value->addr = addr;
}

enum proctal_cmd_val_type proctal_cmd_val_attr_type(proctal_cmd_val_attr a)
{
	return a->type;
}

size_t proctal_cmd_val_attr_alignof(proctal_cmd_val_attr a)
{
	switch (a->type) {
	case PROCTAL_CMD_VAL_TYPE_TEXT:
	case PROCTAL_CMD_VAL_TYPE_BYTE:
		return 1;

	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		switch (((struct proctal_cmd_val_attr_integer *) a->type_attr)->size) {
		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8:
			return alignof (int8_t);

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16:
			return alignof (int16_t);

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32:
			return alignof (int32_t);

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64:
			return alignof (int64_t);
		}

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		switch (((struct proctal_cmd_val_attr_ieee754 *) a->type_attr)->precision) {
		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return alignof (float);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return alignof (double);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return alignof (long double);
		}

	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return alignof (void *);
	}

	return 1;
}

enum proctal_cmd_val_type proctal_cmd_val_type(proctal_cmd_val v)
{
	return proctal_cmd_val_attr_type(&v->attr);
}

size_t proctal_cmd_val_alignof(proctal_cmd_val v)
{
	return proctal_cmd_val_attr_alignof(&v->attr);
}

size_t proctal_cmd_val_sizeof(proctal_cmd_val v)
{
	switch (v->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
		return 1;

	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		switch (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->size) {
		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8:
			return sizeof (int8_t);

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16:
			return sizeof (int16_t);

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32:
			return sizeof (int32_t);

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64:
			return sizeof (int64_t);
		}
		break;

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		switch (((struct proctal_cmd_val_attr_ieee754 *) v->attr.type_attr)->precision) {
		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return sizeof (float);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return sizeof (double);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return sizeof (long double);
		}
		break;

	case PROCTAL_CMD_VAL_TYPE_TEXT:
		return ((struct proctal_cmd_val_str *) v->value)->size;

	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return sizeof (void *);

	case PROCTAL_CMD_VAL_TYPE_INSTRUCTION: {
		struct proctal_cmd_val_ins *value = (struct proctal_cmd_val_ins *) v->value;

		if (value->insn == NULL) {
			return 0;
		}

		return value->insn->size;
	}
	}

	return 1;
}

char *proctal_cmd_val_addr(proctal_cmd_val v)
{
	switch (v->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
	case PROCTAL_CMD_VAL_TYPE_INTEGER:
	case PROCTAL_CMD_VAL_TYPE_IEEE754:
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return (char *) v->value;

	case PROCTAL_CMD_VAL_TYPE_TEXT:
		return (char *) ((struct proctal_cmd_val_str *) v->value)->data;

	case PROCTAL_CMD_VAL_TYPE_INSTRUCTION: {
		struct proctal_cmd_val_ins *value = (struct proctal_cmd_val_ins *) v->value;

		if (value->insn == NULL) {
			return NULL;
		}

		return (char *) value->insn->bytes;
	}
	}

	return NULL;
}

int proctal_cmd_val_add(proctal_cmd_val v1, proctal_cmd_val v2, proctal_cmd_val vr)
{
#define NATIVE_ADD(TYPE) \
	*(TYPE*) vr->value = *(TYPE*) v1->value + *(TYPE*) v2->value; \
	return 1;

	switch (vr->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
		return NATIVE_ADD(unsigned char);

	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		switch (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->size) {
		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_ADD(uint8_t);
			} else {
				return NATIVE_ADD(int8_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_ADD(uint16_t);
			} else {
				return NATIVE_ADD(int16_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_ADD(uint32_t);
			} else {
				return NATIVE_ADD(int32_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_ADD(uint64_t);
			} else {
				return NATIVE_ADD(int64_t);
			}
		}

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		switch (((struct proctal_cmd_val_attr_ieee754 *) vr->attr.type_attr)->precision) {
		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return NATIVE_ADD(float);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return NATIVE_ADD(double);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return NATIVE_ADD(long double);
		}
	}

#undef NATIVE_ADD

	return 0;
}

int proctal_cmd_val_sub(proctal_cmd_val v1, proctal_cmd_val v2, proctal_cmd_val vr)
{
#define NATIVE_SUB(TYPE) \
	*(TYPE*) vr->value = *(TYPE*) v1->value - *(TYPE*) v2->value; \
	return 1;

	switch (vr->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
		return NATIVE_SUB(unsigned char);

	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		switch (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->size) {
		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_SUB(uint8_t);
			} else {
				return NATIVE_SUB(int8_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_SUB(uint16_t);
			} else {
				return NATIVE_SUB(int16_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_SUB(uint32_t);
			} else {
				return NATIVE_SUB(int32_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct proctal_cmd_val_attr_integer *) vr->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_SUB(uint64_t);
			} else {
				return NATIVE_SUB(int64_t);
			}
		}

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		switch (((struct proctal_cmd_val_attr_ieee754 *) vr->attr.type_attr)->precision) {
		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return NATIVE_SUB(float);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return NATIVE_SUB(double);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return NATIVE_SUB(long double);
		}
	}

#undef NATIVE_SUB

	return 0;
}

int proctal_cmd_val_cmp(proctal_cmd_val v1, proctal_cmd_val v2)
{
#define NATIVE_CMP(TYPE) \
	(*(TYPE*) v1->value == *(TYPE*) v2->value \
		? 0 \
		: (*(TYPE*) v1->value > *(TYPE*) v2->value ? 1 : -1))

	switch (v1->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
		return NATIVE_CMP(unsigned char);

	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		switch (((struct proctal_cmd_val_attr_integer *) v1->attr.type_attr)->size) {
		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct proctal_cmd_val_attr_integer *) v1->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_CMP(uint8_t);
			} else {
				return NATIVE_CMP(int8_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct proctal_cmd_val_attr_integer *) v1->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_CMP(uint16_t);
			} else {
				return NATIVE_CMP(int16_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct proctal_cmd_val_attr_integer *) v1->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_CMP(uint32_t);
			} else {
				return NATIVE_CMP(int32_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct proctal_cmd_val_attr_integer *) v1->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_CMP(uint64_t);
			} else {
				return NATIVE_CMP(int64_t);
			}
		}

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		switch (((struct proctal_cmd_val_attr_ieee754 *) v1->attr.type_attr)->precision) {
		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return NATIVE_CMP(float);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return NATIVE_CMP(double);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return NATIVE_CMP(long double);
		}

	case PROCTAL_CMD_VAL_TYPE_TEXT:
		return strncmp(
			((struct proctal_cmd_val_str *) v1->value)->data,
			((struct proctal_cmd_val_str *) v2->value)->data,
			((struct proctal_cmd_val_str *) v1->value)->size);
	}

#undef NATIVE_CMP

	return 0;
}

int proctal_cmd_val_print(proctal_cmd_val v, FILE *f)
{
#define PRINTFV(FORMAT, TYPE, VALUE) \
	fprintf(f, FORMAT, *(TYPE *) VALUE)

#define PRINTF(FORMAT, TYPE) \
	PRINTFV(FORMAT, TYPE, v->value)

	switch (v->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
		return PRINTF("%u", unsigned char);

	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		switch (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->size) {
		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return PRINTF("%" PRIu8, uint8_t);
			} else {
				return PRINTF("%" PRIi8, int8_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return PRINTF("%" PRIu16, uint16_t);
			} else {
				return PRINTF("%" PRIi16, int16_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return PRINTF("%" PRIu32, uint32_t);
			} else {
				return PRINTF("%" PRIi32, int32_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return PRINTF("%" PRIu64, uint64_t);
			} else {
				return PRINTF("%" PRIi64, int64_t);
			}
		}

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		switch (((struct proctal_cmd_val_attr_ieee754 *) v->attr.type_attr)->precision) {
		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return PRINTF("%f", float);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return PRINTF("%f", double);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return PRINTF("%Lf", long double);
		}

	case PROCTAL_CMD_VAL_TYPE_TEXT:
		if (((struct proctal_cmd_val_attr_text *) v->attr.type_attr)->charset == PROCTAL_CMD_VAL_TYPE_TEXT_CHARSET_ASCII) {
			return PRINTFV("%c", char, (char *) ((struct proctal_cmd_val_str *) v->value)->data);
		}

	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return PRINTF("%lx", unsigned long);

	case PROCTAL_CMD_VAL_TYPE_INSTRUCTION: {
		struct proctal_cmd_val_ins *value = ((struct proctal_cmd_val_ins *) v->value);

		if (value->insn == NULL) {
			return 0;
		}

		return fprintf(f, "%s\t%s", value->insn->mnemonic, value->insn->op_str);
	}
	}

#undef PRINTF
#undef PRINTFV

	return 0;
}

int proctal_cmd_val_scan(proctal_cmd_val v, FILE *f)
{
#define SCANFV(FORMAT, TYPE, VALUE) \
	(fscanf(f, FORMAT, (TYPE *) VALUE) == 1 ? 1 : 0)

#define SCANF(FORMAT, TYPE) \
	SCANFV(FORMAT, TYPE, v->value)

	switch (v->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
		return SCANF("%hhu", unsigned char);

	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		switch (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->size) {
		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu8, uint8_t);
			} else {
				return SCANF("%" SCNi8, int8_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu16, uint16_t);
			} else {
				return SCANF("%" SCNi16, int16_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu32, uint32_t);
			} else {
				return SCANF("%" SCNi32, int32_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu64, uint64_t);
			} else {
				return SCANF("%" SCNi64, int64_t);
			}
		}

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		switch (((struct proctal_cmd_val_attr_ieee754 *) v->attr.type_attr)->precision) {
		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return SCANF("%f", float);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return SCANF("%lf", double);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return SCANF("%Lf", long double);
		}

	case PROCTAL_CMD_VAL_TYPE_TEXT:
		if (((struct proctal_cmd_val_attr_text *) v->attr.type_attr)->charset == PROCTAL_CMD_VAL_TYPE_TEXT_CHARSET_ASCII) {
			return SCANFV("%c", char, ((struct proctal_cmd_val_str *) v->value)->data);
		}

	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return SCANF("%lx", unsigned long);
	}

#undef SCANF
#undef SCANFV

	return 0;
}

int proctal_cmd_val_parse(proctal_cmd_val v, const char *s)
{
#define SCANFV(FORMAT, TYPE, VALUE) \
	(sscanf(s, FORMAT, (TYPE *) VALUE) == 1 ? 1 : 0)

#define SCANF(FORMAT, TYPE) \
	SCANFV(FORMAT, TYPE, v->value)

	switch (v->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
		return SCANF("%hhu", unsigned char);

	case PROCTAL_CMD_VAL_TYPE_INTEGER:
		switch (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->size) {
		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu8, uint8_t);
			} else {
				return SCANF("%" SCNi8, int8_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu16, uint16_t);
			} else {
				return SCANF("%" SCNi16, int16_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu32, uint32_t);
			} else {
				return SCANF("%" SCNi32, int32_t);
			}

		case PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct proctal_cmd_val_attr_integer *) v->attr.type_attr)->sign == PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu64, uint64_t);
			} else {
				return SCANF("%" SCNi64, int64_t);
			}
		}

	case PROCTAL_CMD_VAL_TYPE_IEEE754:
		switch (((struct proctal_cmd_val_attr_ieee754 *) v->attr.type_attr)->precision) {
		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return SCANF("%f", float);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return SCANF("%lf", double);

		case PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return SCANF("%Lf", long double);
		}

	case PROCTAL_CMD_VAL_TYPE_TEXT:
		if (((struct proctal_cmd_val_attr_text *) v->attr.type_attr)->charset == PROCTAL_CMD_VAL_TYPE_TEXT_CHARSET_ASCII) {
			return SCANFV("%c", char, ((struct proctal_cmd_val_str *) v->value)->data);
		}

	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
		return SCANF("%lx", unsigned long);

	case PROCTAL_CMD_VAL_TYPE_INSTRUCTION: {
		struct proctal_cmd_val_ins *value = ((struct proctal_cmd_val_ins *) v->value);

		if (value->insn) {
			cs_free(value->insn, 1);
			value->insn = NULL;
		}

		// The value structure was programmed to hold a reference to a
		// capstone disassembled instruction because it's very
		// convenient. To remain compatible with existing code, we're
		// going to assemble the code with keystone and then
		// disassemble the result with capstone so as to keep the
		// remaining code as is. Also, it ensures we only parse the
		// first instruction that shows up and ignore the rest.

		ks_engine *ks;

		size_t count;
		unsigned char *encode;
		size_t size;

		if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) {
			return 0;
		}

		if (ks_asm(ks, s, 0, &encode, &size, &count) != KS_ERR_OK) {
			return 0;
		}

		int parse_bin = proctal_cmd_val_parse_bin(v, (const char *) encode, count);

		ks_free(encode);
		ks_close(ks);

		return parse_bin ? 1 : 0;
	}
	}

#undef SCANF
#undef SCANFV

	return 0;
}

int proctal_cmd_val_parse_bin(proctal_cmd_val v, const char *s, size_t length)
{
	switch (v->attr.type) {
	case PROCTAL_CMD_VAL_TYPE_BYTE:
	case PROCTAL_CMD_VAL_TYPE_INTEGER:
	case PROCTAL_CMD_VAL_TYPE_IEEE754:
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
	case PROCTAL_CMD_VAL_TYPE_TEXT: {
		size_t size = proctal_cmd_val_sizeof(v);

		if (size > length) {
			return 0;
		}

		memcpy(proctal_cmd_val_addr(v), s, size);

		return size;
	}

	case PROCTAL_CMD_VAL_TYPE_INSTRUCTION: {
		struct proctal_cmd_val_ins *value = ((struct proctal_cmd_val_ins *) v->value);

		if (value->insn) {
			cs_free(value->insn, 1);
			value->insn = NULL;
		}

		csh handle;

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
			return 0;
		}

		int count = cs_disasm(handle, (const unsigned char *) s, length, (unsigned long int) value->addr, 1, &value->insn);

		cs_close(&handle);

		if (count > 0) {
			return value->insn->size;
		}
	}
	}

	return 0;
}

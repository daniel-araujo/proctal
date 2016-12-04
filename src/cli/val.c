#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "val.h"

static struct cli_val *nil = NULL;

struct cli_val_attr_ieee754 {
	enum cli_val_type_ieee754_precision precision;
};

struct cli_val_attr_text {
	enum cli_val_type_text_charset charset;
};

struct cli_val_attr_integer {
	enum cli_val_type_integer_size size;
	enum cli_val_type_integer_sign sign;
};

struct cli_val_attr {
	enum cli_val_type type;
	void *type_attr;
	enum cli_val_type_endianness endianness;
};

struct cli_val_str {
	size_t size;
	char *data;
};

struct cli_val_ins {
	void *addr;
	cs_insn *insn;
};

struct cli_val {
	struct cli_val_attr attr;
	void *value;
};

cli_val_attr cli_val_attr_create(enum cli_val_type type)
{
	cli_val_attr a = (cli_val_attr) malloc(sizeof *a);

	if (a == NULL) {
		return NULL;
	}

	a->type = type;
	a->type_attr = NULL;
	a->endianness = CLI_VAL_TYPE_ENDIANNESS_LITTLE;

	switch (a->type) {
	case CLI_VAL_TYPE_INTEGER: {
		struct cli_val_attr_integer *ta = (struct cli_val_attr_integer *) malloc(sizeof *ta);

		if (ta == NULL) {
			free(a);
			return NULL;
		}

		ta->size = CLI_VAL_TYPE_INTEGER_SIZE_8;
		ta->sign = CLI_VAL_TYPE_INTEGER_SIGN_2SCMPL;

		a->type_attr = ta;
		break;
	}
	case CLI_VAL_TYPE_IEEE754: {
		struct cli_val_attr_ieee754 *ta = (struct cli_val_attr_ieee754 *) malloc(sizeof *ta);

		if (ta == NULL) {
			free(a);
			return NULL;
		}

		ta->precision = CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE;

		a->type_attr = ta;
		break;
	}
	case CLI_VAL_TYPE_TEXT: {
		struct cli_val_attr_text *ta = (struct cli_val_attr_text *) malloc(sizeof *ta);

		if (ta == NULL) {
			free(a);
			return NULL;
		}

		ta->charset = CLI_VAL_TYPE_TEXT_CHARSET_ASCII;

		a->type_attr = ta;
		break;
	}
	}

	return a;
}

void cli_val_attr_destroy(cli_val_attr a)
{
	if (a->type_attr) {
		free(a->type_attr);
	}

	free(a);
}

void cli_val_attr_set_endianness(
	cli_val_attr a,
	enum cli_val_type_endianness endianness)
{
	a->endianness = endianness;
}

void cli_val_attr_set_integer_size(
	cli_val_attr a,
	enum cli_val_type_integer_size size)
{
	if (a->type != CLI_VAL_TYPE_INTEGER) {
		return;
	}

	((struct cli_val_attr_integer *) a->type_attr)->size = size;
}

void cli_val_attr_set_integer_sign(
	cli_val_attr a,
	enum cli_val_type_integer_sign sign)
{
	if (a->type != CLI_VAL_TYPE_INTEGER) {
		return;
	}

	((struct cli_val_attr_integer *) a->type_attr)->sign = sign;
}

void cli_val_attr_set_ieee754_precision(
	cli_val_attr a,
	enum cli_val_type_ieee754_precision precision)
{
	if (a->type != CLI_VAL_TYPE_IEEE754) {
		return;
	}

	((struct cli_val_attr_ieee754 *) a->type_attr)->precision = precision;
}

void cli_val_attr_set_text_charset(
	cli_val_attr a,
	enum cli_val_type_text_charset charset)
{
	if (a->type != CLI_VAL_TYPE_TEXT) {
		return;
	}

	((struct cli_val_attr_text *) a->type_attr)->charset = charset;
}

void cli_val_destroy(cli_val v)
{
	switch (v->attr.type) {
	case CLI_VAL_TYPE_BYTE:
	case CLI_VAL_TYPE_INTEGER:
	case CLI_VAL_TYPE_IEEE754:
	case CLI_VAL_TYPE_ADDRESS:
		if (v->value) {
			free(v->value);
		}
		break;

	case CLI_VAL_TYPE_INSTRUCTION: {
		struct cli_val_ins *value = (struct cli_val_ins *) v->value;

		if (value->insn) {
			cs_free(value->insn, 1);
		}

		free(v->value);
		break;
	}

	case CLI_VAL_TYPE_TEXT: {
		if (v->value == NULL) {
			break;
		}

		struct cli_val_str *value = (struct cli_val_str *) v->value;

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

cli_val cli_val_create(cli_val_attr a)
{
	cli_val v = (cli_val) malloc(sizeof *v);

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
			cli_val_destroy(v); \
			return NULL; \
		} \
		*ta2 = *ta; \
		v->attr.type_attr = ta2; \
	} while (0)

	switch (a->type) {
	case CLI_VAL_TYPE_INTEGER:
		COPY_TYPE_ATTR(struct cli_val_attr_integer);
		break;

	case CLI_VAL_TYPE_IEEE754:
		COPY_TYPE_ATTR(struct cli_val_attr_ieee754);
		break;

	case CLI_VAL_TYPE_TEXT:
		COPY_TYPE_ATTR(struct cli_val_attr_text);
		break;
	}

#undef COPY_TYPE_ATTR

	switch (v->attr.type) {
	case CLI_VAL_TYPE_BYTE:
	case CLI_VAL_TYPE_INTEGER:
	case CLI_VAL_TYPE_IEEE754:
	case CLI_VAL_TYPE_ADDRESS:
		v->value = malloc(cli_val_sizeof(v));

		if (v->value == NULL) {
			cli_val_destroy(v);
			return NULL;
		}
		break;

	case CLI_VAL_TYPE_TEXT:
		if (((struct cli_val_attr_text *) v->attr.type_attr)->charset == CLI_VAL_TYPE_TEXT_CHARSET_ASCII) {
			struct cli_val_str *value = malloc(sizeof *value);

			if (value == NULL) {
				cli_val_destroy(v);
				return NULL;
			}

			value->size = 1;
			value->data = (char *) malloc(value->size);

			if (value->data == NULL) {
				cli_val_destroy(v);
				return NULL;
			}

			v->value = value;
		}
		break;

	case CLI_VAL_TYPE_INSTRUCTION: {
		struct cli_val_ins *value = malloc(sizeof *value);

		if (value == NULL) {
			cli_val_destroy(v);
			return NULL;
		}

		value->addr = 0;
		value->insn = NULL;

		v->value = value;
		break;
	}

	default:
		cli_val_destroy(v);
		return NULL;
	}

	return v;
}

void cli_val_set_instruction_addr(cli_val v, void *addr)
{
	if (v->attr.type != CLI_VAL_TYPE_INSTRUCTION) {
		return;
	}

	struct cli_val_ins *value = (struct cli_val_ins *) v->value;

	value->addr = addr;
}

enum cli_val_type cli_val_attr_type(cli_val_attr a)
{
	return a->type;
}

size_t cli_val_attr_alignof(cli_val_attr a)
{
	switch (a->type) {
	case CLI_VAL_TYPE_TEXT:
	case CLI_VAL_TYPE_BYTE:
		return 1;

	case CLI_VAL_TYPE_INTEGER:
		switch (((struct cli_val_attr_integer *) a->type_attr)->size) {
		case CLI_VAL_TYPE_INTEGER_SIZE_8:
			return alignof (int8_t);

		case CLI_VAL_TYPE_INTEGER_SIZE_16:
			return alignof (int16_t);

		case CLI_VAL_TYPE_INTEGER_SIZE_32:
			return alignof (int32_t);

		case CLI_VAL_TYPE_INTEGER_SIZE_64:
			return alignof (int64_t);
		}

	case CLI_VAL_TYPE_IEEE754:
		switch (((struct cli_val_attr_ieee754 *) a->type_attr)->precision) {
		case CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return alignof (float);

		case CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return alignof (double);

		case CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return alignof (long double);
		}

	case CLI_VAL_TYPE_ADDRESS:
		return alignof (void *);
	}

	return 1;
}

enum cli_val_type cli_val_type(cli_val v)
{
	return cli_val_attr_type(&v->attr);
}

size_t cli_val_alignof(cli_val v)
{
	return cli_val_attr_alignof(&v->attr);
}

size_t cli_val_sizeof(cli_val v)
{
	switch (v->attr.type) {
	case CLI_VAL_TYPE_BYTE:
		return 1;

	case CLI_VAL_TYPE_INTEGER:
		switch (((struct cli_val_attr_integer *) v->attr.type_attr)->size) {
		case CLI_VAL_TYPE_INTEGER_SIZE_8:
			return sizeof (int8_t);

		case CLI_VAL_TYPE_INTEGER_SIZE_16:
			return sizeof (int16_t);

		case CLI_VAL_TYPE_INTEGER_SIZE_32:
			return sizeof (int32_t);

		case CLI_VAL_TYPE_INTEGER_SIZE_64:
			return sizeof (int64_t);
		}
		break;

	case CLI_VAL_TYPE_IEEE754:
		switch (((struct cli_val_attr_ieee754 *) v->attr.type_attr)->precision) {
		case CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return sizeof (float);

		case CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return sizeof (double);

		case CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return sizeof (long double);
		}
		break;

	case CLI_VAL_TYPE_TEXT:
		return ((struct cli_val_str *) v->value)->size;

	case CLI_VAL_TYPE_ADDRESS:
		return sizeof (void *);

	case CLI_VAL_TYPE_INSTRUCTION: {
		struct cli_val_ins *value = (struct cli_val_ins *) v->value;

		if (value->insn == NULL) {
			return 0;
		}

		return value->insn->size;
	}
	}

	return 1;
}

char *cli_val_addr(cli_val v)
{
	switch (v->attr.type) {
	case CLI_VAL_TYPE_BYTE:
	case CLI_VAL_TYPE_INTEGER:
	case CLI_VAL_TYPE_IEEE754:
	case CLI_VAL_TYPE_ADDRESS:
		return (char *) v->value;

	case CLI_VAL_TYPE_TEXT:
		return (char *) ((struct cli_val_str *) v->value)->data;

	case CLI_VAL_TYPE_INSTRUCTION: {
		struct cli_val_ins *value = (struct cli_val_ins *) v->value;

		if (value->insn == NULL) {
			return NULL;
		}

		return (char *) value->insn->bytes;
	}
	}

	return NULL;
}

int cli_val_add(cli_val v1, cli_val v2, cli_val vr)
{
#define NATIVE_ADD(TYPE) \
	*(TYPE*) vr->value = *(TYPE*) v1->value + *(TYPE*) v2->value; \
	return 1;

	switch (vr->attr.type) {
	case CLI_VAL_TYPE_BYTE:
		return NATIVE_ADD(unsigned char);

	case CLI_VAL_TYPE_INTEGER:
		switch (((struct cli_val_attr_integer *) vr->attr.type_attr)->size) {
		case CLI_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct cli_val_attr_integer *) vr->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_ADD(uint8_t);
			} else {
				return NATIVE_ADD(int8_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct cli_val_attr_integer *) vr->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_ADD(uint16_t);
			} else {
				return NATIVE_ADD(int16_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct cli_val_attr_integer *) vr->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_ADD(uint32_t);
			} else {
				return NATIVE_ADD(int32_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct cli_val_attr_integer *) vr->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_ADD(uint64_t);
			} else {
				return NATIVE_ADD(int64_t);
			}
		}

	case CLI_VAL_TYPE_IEEE754:
		switch (((struct cli_val_attr_ieee754 *) vr->attr.type_attr)->precision) {
		case CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return NATIVE_ADD(float);

		case CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return NATIVE_ADD(double);

		case CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return NATIVE_ADD(long double);
		}
	}

#undef NATIVE_ADD

	return 0;
}

int cli_val_sub(cli_val v1, cli_val v2, cli_val vr)
{
#define NATIVE_SUB(TYPE) \
	*(TYPE*) vr->value = *(TYPE*) v1->value - *(TYPE*) v2->value; \
	return 1;

	switch (vr->attr.type) {
	case CLI_VAL_TYPE_BYTE:
		return NATIVE_SUB(unsigned char);

	case CLI_VAL_TYPE_INTEGER:
		switch (((struct cli_val_attr_integer *) vr->attr.type_attr)->size) {
		case CLI_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct cli_val_attr_integer *) vr->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_SUB(uint8_t);
			} else {
				return NATIVE_SUB(int8_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct cli_val_attr_integer *) vr->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_SUB(uint16_t);
			} else {
				return NATIVE_SUB(int16_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct cli_val_attr_integer *) vr->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_SUB(uint32_t);
			} else {
				return NATIVE_SUB(int32_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct cli_val_attr_integer *) vr->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_SUB(uint64_t);
			} else {
				return NATIVE_SUB(int64_t);
			}
		}

	case CLI_VAL_TYPE_IEEE754:
		switch (((struct cli_val_attr_ieee754 *) vr->attr.type_attr)->precision) {
		case CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return NATIVE_SUB(float);

		case CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return NATIVE_SUB(double);

		case CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return NATIVE_SUB(long double);
		}
	}

#undef NATIVE_SUB

	return 0;
}

int cli_val_cmp(cli_val v1, cli_val v2)
{
#define NATIVE_CMP(TYPE) \
	(*(TYPE*) v1->value == *(TYPE*) v2->value \
		? 0 \
		: (*(TYPE*) v1->value > *(TYPE*) v2->value ? 1 : -1))

	switch (v1->attr.type) {
	case CLI_VAL_TYPE_BYTE:
		return NATIVE_CMP(unsigned char);

	case CLI_VAL_TYPE_INTEGER:
		switch (((struct cli_val_attr_integer *) v1->attr.type_attr)->size) {
		case CLI_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct cli_val_attr_integer *) v1->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_CMP(uint8_t);
			} else {
				return NATIVE_CMP(int8_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct cli_val_attr_integer *) v1->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_CMP(uint16_t);
			} else {
				return NATIVE_CMP(int16_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct cli_val_attr_integer *) v1->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_CMP(uint32_t);
			} else {
				return NATIVE_CMP(int32_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct cli_val_attr_integer *) v1->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return NATIVE_CMP(uint64_t);
			} else {
				return NATIVE_CMP(int64_t);
			}
		}

	case CLI_VAL_TYPE_IEEE754:
		switch (((struct cli_val_attr_ieee754 *) v1->attr.type_attr)->precision) {
		case CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return NATIVE_CMP(float);

		case CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return NATIVE_CMP(double);

		case CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return NATIVE_CMP(long double);
		}

	case CLI_VAL_TYPE_TEXT:
		return strncmp(
			((struct cli_val_str *) v1->value)->data,
			((struct cli_val_str *) v2->value)->data,
			((struct cli_val_str *) v1->value)->size);
	}

#undef NATIVE_CMP

	return 0;
}

int cli_val_print(cli_val v, FILE *f)
{
#define PRINTFV(FORMAT, TYPE, VALUE) \
	fprintf(f, FORMAT, *(TYPE *) VALUE)

#define PRINTF(FORMAT, TYPE) \
	PRINTFV(FORMAT, TYPE, v->value)

	switch (v->attr.type) {
	case CLI_VAL_TYPE_BYTE:
		return PRINTF("%x", unsigned char);

	case CLI_VAL_TYPE_INTEGER:
		switch (((struct cli_val_attr_integer *) v->attr.type_attr)->size) {
		case CLI_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return PRINTF("%" PRIu8, uint8_t);
			} else {
				return PRINTF("%" PRIi8, int8_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return PRINTF("%" PRIu16, uint16_t);
			} else {
				return PRINTF("%" PRIi16, int16_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return PRINTF("%" PRIu32, uint32_t);
			} else {
				return PRINTF("%" PRIi32, int32_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return PRINTF("%" PRIu64, uint64_t);
			} else {
				return PRINTF("%" PRIi64, int64_t);
			}
		}

	case CLI_VAL_TYPE_IEEE754:
		switch (((struct cli_val_attr_ieee754 *) v->attr.type_attr)->precision) {
		case CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return PRINTF("%f", float);

		case CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return PRINTF("%f", double);

		case CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return PRINTF("%Lf", long double);
		}

	case CLI_VAL_TYPE_TEXT:
		if (((struct cli_val_attr_text *) v->attr.type_attr)->charset == CLI_VAL_TYPE_TEXT_CHARSET_ASCII) {
			return PRINTFV("%c", char, (char *) ((struct cli_val_str *) v->value)->data);
		}

	case CLI_VAL_TYPE_ADDRESS:
		return PRINTF("%lx", unsigned long);

	case CLI_VAL_TYPE_INSTRUCTION: {
		struct cli_val_ins *value = ((struct cli_val_ins *) v->value);

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

int cli_val_scan(cli_val v, FILE *f)
{
#define SCANFV(FORMAT, TYPE, VALUE) \
	(fscanf(f, FORMAT, (TYPE *) VALUE) == 1 ? 1 : 0)

#define SCANF(FORMAT, TYPE) \
	SCANFV(FORMAT, TYPE, v->value)

	switch (v->attr.type) {
	case CLI_VAL_TYPE_BYTE:
		return SCANF("%hhx", unsigned char);

	case CLI_VAL_TYPE_INTEGER:
		switch (((struct cli_val_attr_integer *) v->attr.type_attr)->size) {
		case CLI_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu8, uint8_t);
			} else {
				return SCANF("%" SCNi8, int8_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu16, uint16_t);
			} else {
				return SCANF("%" SCNi16, int16_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu32, uint32_t);
			} else {
				return SCANF("%" SCNi32, int32_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu64, uint64_t);
			} else {
				return SCANF("%" SCNi64, int64_t);
			}
		}

	case CLI_VAL_TYPE_IEEE754:
		switch (((struct cli_val_attr_ieee754 *) v->attr.type_attr)->precision) {
		case CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return SCANF("%f", float);

		case CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return SCANF("%lf", double);

		case CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return SCANF("%Lf", long double);
		}

	case CLI_VAL_TYPE_TEXT:
		if (((struct cli_val_attr_text *) v->attr.type_attr)->charset == CLI_VAL_TYPE_TEXT_CHARSET_ASCII) {
			return SCANFV("%c", char, ((struct cli_val_str *) v->value)->data);
		}

	case CLI_VAL_TYPE_ADDRESS:
		return SCANF("%lx", unsigned long);
	}

#undef SCANF
#undef SCANFV

	return 0;
}

int cli_val_parse(cli_val v, const char *s)
{
#define SCANFV(FORMAT, TYPE, VALUE) \
	(sscanf(s, FORMAT, (TYPE *) VALUE) == 1 ? 1 : 0)

#define SCANF(FORMAT, TYPE) \
	SCANFV(FORMAT, TYPE, v->value)

	switch (v->attr.type) {
	case CLI_VAL_TYPE_BYTE:
		return SCANF("%hhx", unsigned char);

	case CLI_VAL_TYPE_INTEGER:
		switch (((struct cli_val_attr_integer *) v->attr.type_attr)->size) {
		case CLI_VAL_TYPE_INTEGER_SIZE_8:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu8, uint8_t);
			} else {
				return SCANF("%" SCNi8, int8_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_16:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu16, uint16_t);
			} else {
				return SCANF("%" SCNi16, int16_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_32:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu32, uint32_t);
			} else {
				return SCANF("%" SCNi32, int32_t);
			}

		case CLI_VAL_TYPE_INTEGER_SIZE_64:
			if (((struct cli_val_attr_integer *) v->attr.type_attr)->sign == CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED) {
				return SCANF("%" SCNu64, uint64_t);
			} else {
				return SCANF("%" SCNi64, int64_t);
			}
		}

	case CLI_VAL_TYPE_IEEE754:
		switch (((struct cli_val_attr_ieee754 *) v->attr.type_attr)->precision) {
		case CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE:
			return SCANF("%f", float);

		case CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE:
			return SCANF("%lf", double);

		case CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED:
			return SCANF("%Lf", long double);
		}

	case CLI_VAL_TYPE_TEXT:
		if (((struct cli_val_attr_text *) v->attr.type_attr)->charset == CLI_VAL_TYPE_TEXT_CHARSET_ASCII) {
			return SCANFV("%c", char, ((struct cli_val_str *) v->value)->data);
		}

	case CLI_VAL_TYPE_ADDRESS:
		return SCANF("%lx", unsigned long);

	case CLI_VAL_TYPE_INSTRUCTION: {
		struct cli_val_ins *value = ((struct cli_val_ins *) v->value);

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
			ks_close(ks);
			return 0;
		}

		int parse_bin = cli_val_parse_bin(v, (const char *) encode, size);

		ks_free(encode);
		ks_close(ks);

		return parse_bin ? 1 : 0;
	}
	}

#undef SCANF
#undef SCANFV

	return 0;
}

int cli_val_parse_bin(cli_val v, const char *s, size_t length)
{
	switch (v->attr.type) {
	case CLI_VAL_TYPE_BYTE:
	case CLI_VAL_TYPE_INTEGER:
	case CLI_VAL_TYPE_IEEE754:
	case CLI_VAL_TYPE_ADDRESS:
	case CLI_VAL_TYPE_TEXT: {
		size_t size = cli_val_sizeof(v);

		if (size > length) {
			return 0;
		}

		memcpy(cli_val_addr(v), s, size);

		return size;
	}

	case CLI_VAL_TYPE_INSTRUCTION: {
		struct cli_val_ins *value = ((struct cli_val_ins *) v->value);

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

cli_val cli_val_nil(void)
{
	return nil;
}

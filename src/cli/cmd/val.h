#ifndef CMD_VAL_H
#define CMD_VAL_H

#include <stdio.h>
#include <stdalign.h>

enum proctal_cmd_val_type {
	PROCTAL_CMD_VAL_TYPE_BYTE,
	PROCTAL_CMD_VAL_TYPE_INTEGER,
	PROCTAL_CMD_VAL_TYPE_IEEE754,
	PROCTAL_CMD_VAL_TYPE_TEXT,
	PROCTAL_CMD_VAL_TYPE_ADDRESS,
};

enum proctal_cmd_val_type_endianness {
	PROCTAL_CMD_VAL_TYPE_ENDIANNESS_LITTLE,
};

enum proctal_cmd_val_type_integer_size {
	PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_8,
	PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_16,
	PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_32,
	PROCTAL_CMD_VAL_TYPE_INTEGER_SIZE_64,
};

enum proctal_cmd_val_type_integer_sign {
	PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_UNSIGNED,
	PROCTAL_CMD_VAL_TYPE_INTEGER_SIGN_2SCMPL,
};

enum proctal_cmd_val_type_text_charset {
	PROCTAL_CMD_VAL_TYPE_TEXT_CHARSET_ASCII,
};

enum proctal_cmd_val_type_ieee754_precision {
	PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_SINGLE,
	PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_DOUBLE,
	PROCTAL_CMD_VAL_TYPE_IEEE754_PRECISION_EXTENDED,
};

typedef struct proctal_cmd_val_attr *proctal_cmd_val_attr;
typedef struct proctal_cmd_val *proctal_cmd_val;

proctal_cmd_val_attr proctal_cmd_val_attr_create(enum proctal_cmd_val_type type);
void proctal_cmd_val_attr_destroy(proctal_cmd_val_attr a);

void proctal_cmd_val_attr_set_endianness(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_endianness endianness);

void proctal_cmd_val_attr_set_integer_size(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_integer_size size);
void proctal_cmd_val_attr_set_integer_sign(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_integer_sign sign);

void proctal_cmd_val_attr_set_ieee754_precision(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_ieee754_precision precision);

void proctal_cmd_val_attr_set_text_charset(
	proctal_cmd_val_attr a,
	enum proctal_cmd_val_type_text_charset charset);

enum proctal_cmd_val_type proctal_cmd_val_attr_type(proctal_cmd_val_attr a);
size_t proctal_cmd_val_attr_alignof(proctal_cmd_val_attr a);

proctal_cmd_val proctal_cmd_val_create(proctal_cmd_val_attr a);
void proctal_cmd_val_destroy(proctal_cmd_val v);

enum proctal_cmd_val_type proctal_cmd_val_type(proctal_cmd_val v);
size_t proctal_cmd_val_alignof(proctal_cmd_val v);
size_t proctal_cmd_val_sizeof(proctal_cmd_val v);
char *proctal_cmd_val_addr(proctal_cmd_val v);
int proctal_cmd_val_add(proctal_cmd_val v1, proctal_cmd_val v2, proctal_cmd_val vr);
int proctal_cmd_val_sub(proctal_cmd_val v1, proctal_cmd_val v2, proctal_cmd_val vr);
int proctal_cmd_val_cmp(proctal_cmd_val v1, proctal_cmd_val v2);
int proctal_cmd_val_print(proctal_cmd_val v, FILE *f);
int proctal_cmd_val_scan(proctal_cmd_val v, FILE *f);
int proctal_cmd_val_parse(proctal_cmd_val v, const char *s);

#endif /* CMD_VAL_H */

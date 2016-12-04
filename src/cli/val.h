#ifndef VAL_H
#define VAL_H

#include <stdio.h>
#include <stdalign.h>

enum cli_val_type {
	CLI_VAL_TYPE_BYTE,
	CLI_VAL_TYPE_INTEGER,
	CLI_VAL_TYPE_IEEE754,
	CLI_VAL_TYPE_TEXT,
	CLI_VAL_TYPE_ADDRESS,
	CLI_VAL_TYPE_INSTRUCTION,
};

enum cli_val_type_endianness {
	CLI_VAL_TYPE_ENDIANNESS_LITTLE,
};

enum cli_val_type_integer_size {
	CLI_VAL_TYPE_INTEGER_SIZE_8,
	CLI_VAL_TYPE_INTEGER_SIZE_16,
	CLI_VAL_TYPE_INTEGER_SIZE_32,
	CLI_VAL_TYPE_INTEGER_SIZE_64,
};

enum cli_val_type_integer_sign {
	CLI_VAL_TYPE_INTEGER_SIGN_UNSIGNED,
	CLI_VAL_TYPE_INTEGER_SIGN_2SCMPL,
};

enum cli_val_type_text_charset {
	CLI_VAL_TYPE_TEXT_CHARSET_ASCII,
};

enum cli_val_type_ieee754_precision {
	CLI_VAL_TYPE_IEEE754_PRECISION_SINGLE,
	CLI_VAL_TYPE_IEEE754_PRECISION_DOUBLE,
	CLI_VAL_TYPE_IEEE754_PRECISION_EXTENDED,
};

typedef struct cli_val_attr *cli_val_attr;
typedef struct cli_val *cli_val;

cli_val_attr cli_val_attr_create(enum cli_val_type type);
void cli_val_attr_destroy(cli_val_attr a);

void cli_val_attr_set_endianness(
	cli_val_attr a,
	enum cli_val_type_endianness endianness);

void cli_val_attr_set_integer_size(
	cli_val_attr a,
	enum cli_val_type_integer_size size);
void cli_val_attr_set_integer_sign(
	cli_val_attr a,
	enum cli_val_type_integer_sign sign);

void cli_val_attr_set_ieee754_precision(
	cli_val_attr a,
	enum cli_val_type_ieee754_precision precision);

void cli_val_attr_set_text_charset(
	cli_val_attr a,
	enum cli_val_type_text_charset charset);

enum cli_val_type cli_val_attr_type(cli_val_attr a);
size_t cli_val_attr_alignof(cli_val_attr a);

cli_val cli_val_create(cli_val_attr a);
void cli_val_destroy(cli_val v);

void cli_val_set_instruction_addr(cli_val v, void *addr);

enum cli_val_type cli_val_type(cli_val v);
size_t cli_val_alignof(cli_val v);
size_t cli_val_sizeof(cli_val v);
char *cli_val_addr(cli_val v);
int cli_val_add(cli_val v1, cli_val v2, cli_val vr);
int cli_val_sub(cli_val v1, cli_val v2, cli_val vr);
int cli_val_cmp(cli_val v1, cli_val v2);
int cli_val_print(cli_val v, FILE *f);
int cli_val_scan(cli_val v, FILE *f);
int cli_val_parse(cli_val v, const char *s);
int cli_val_parse_bin(cli_val v, const char *s, size_t length);

cli_val cli_val_nil(void);

#endif /* VAL_H */

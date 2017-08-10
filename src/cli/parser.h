#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include <stdlib.h>

#include "cli/val.h"
#include "cli/val/integer.h"
#include "cli/val/ieee754.h"
#include "cli/val/instruction.h"
#include "cli/val/text.h"
#include "cli/cmd/execute.h"
#include "cli/assembler.h"

int cli_parse_char(const char *s, char *val);
int cli_parse_unsigned_char(const char *s, unsigned char *val);
int cli_parse_signed_char(const char *s, signed char *val);
int cli_parse_short(const char *s, short *val);
int cli_parse_unsigned_short(const char *s, unsigned short *val);
int cli_parse_int(const char *s, int *val);
int cli_parse_unsigned_int(const char *s, unsigned int *val);
int cli_parse_long(const char *s, long *val);
int cli_parse_unsigned_long(const char *s, unsigned long *val);
int cli_parse_long_long(const char *s, long long *val);
int cli_parse_unsigned_long_long(const char *s, unsigned long long *val);
int cli_parse_float(const char *s, float *val);
int cli_parse_double(const char *s, double *val);
int cli_parse_long_double(const char *s, long double *val);
int cli_parse_address(const char *s, void **val);

/*
 * Returns the number of characters to skip to encounter one of the given
 * characters or the NUL character.
 *
 * The characters are also passed in a NUL terminated string.
 */
size_t cli_parse_skip_chars(const char *s, const char *chars);

/*
 * Returns the number of characters to skip to encounter one of the given
 * characters or reaching the length of the string.
 *
 * The characters are also passed in a NUL terminated string.
 */
size_t cli_parse_skip_chars2(const char *s, size_t length, const char *chars);

/*
 * Returns the number of characters to skip before encountering either the NUL
 * characters or one of the given characters.
 *
 * The characters are also passed in a NUL terminated string.
 */
size_t cli_parse_skip_until_chars(const char *s, const char *chars);

/*
 * Returns the number of characters to skip before reaching the length of the
 * string or one of the given characters.
 *
 * The characters are passed in a NUL terminated string.
 */
size_t cli_parse_skip_until_chars2(const char *s, size_t length, const char *chars);

int cli_parse_is_hex_digit(int s);

int cli_parse_val_type(const char *s, enum cli_val_type* val);
int cli_parse_val_integer_endianness(const char *s, enum cli_val_integer_endianness* val);
int cli_parse_val_integer_size(const char *s, enum cli_val_integer_size* val);
int cli_parse_val_integer_sign(const char *s, enum cli_val_integer_sign *val);
int cli_parse_val_ieee754_precision(const char *s, enum cli_val_ieee754_precision *val);
int cli_parse_val_text_encoding(const char *s, enum cli_val_text_encoding *val);
int cli_parse_val_instruction_architecture(const char *s, enum cli_val_instruction_architecture *val);
int cli_parse_val_instruction_syntax(const char *s, enum cli_val_instruction_syntax *val);
int cli_parse_cmd_execute_format(const char *s, enum cli_cmd_execute_format *val);
int cli_parse_assembler_architecture(const char *s, enum cli_assembler_architecture *val);
int cli_parse_assembler_syntax(const char *s, enum cli_assembler_syntax *val);

#endif /* CLI_PARSER_H */

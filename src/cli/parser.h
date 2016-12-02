#ifndef PARSER_H
#define PARSER_H

int cli_parse_char(const char *s, char *val);
int cli_parse_uchar(const char *s, unsigned char *val);
int cli_parse_schar(const char *s, signed char *val);
int cli_parse_short(const char *s, short *val);
int cli_parse_ushort(const char *s, unsigned short *val);
int cli_parse_int(const char *s, int *val);
int cli_parse_uint(const char *s, unsigned int *val);
int cli_parse_long(const char *s, long *val);
int cli_parse_ulong(const char *s, unsigned long *val);
int cli_parse_longlong(const char *s, long long *val);
int cli_parse_ulonglong(const char *s, unsigned long long *val);
int cli_parse_float(const char *s, float *val);
int cli_parse_double(const char *s, double *val);
int cli_parse_longdouble(const char *s, long double *val);
int cli_parse_address(const char *s, void **val);

#endif /* PARSER_H */

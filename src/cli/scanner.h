#ifndef CLI_SCANNER_H
#define CLI_SCANNER_H

#include <stdio.h>

size_t cli_scan_skip_chars(FILE *f, const char *chars);

size_t cli_scan_skip_until_chars(FILE *f, const char *chars);

#endif /* CLI_SCANNER_H */

#ifndef CLI_PATTERN_H
#define CLI_PATTERN_H

#include <stdlib.h>

#define CLI_PATTERN_ERROR_INVALID_PATTERN 1
#define CLI_PATTERN_ERROR_OUT_OF_MEMORY 2
#define CLI_PATTERN_ERROR_EMPTY_PATTERN 3
#define CLI_PATTERN_ERROR_MISSING_WHITESPACE 4
#define CLI_PATTERN_ERROR_COMPILE_PATTERN 5

typedef struct cli_pattern *cli_pattern;

cli_pattern cli_pattern_create(void);

void cli_pattern_destroy(cli_pattern cp);

int cli_pattern_compile(cli_pattern cp, const char *s);

void cli_pattern_new(cli_pattern cp);

int cli_pattern_ready(cli_pattern cp);

int cli_pattern_input(cli_pattern cp, const char *data, size_t size);

int cli_pattern_finished(cli_pattern cp);

int cli_pattern_matched(cli_pattern cp);

int cli_pattern_error(cli_pattern cp);

int cli_pattern_error_compile_offset(cli_pattern cp);

#endif /* CLI_PATTERN_H */

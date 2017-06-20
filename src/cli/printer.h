#ifndef CLI_PRINTER_H
#define CLI_PRINTER_H

#include "api/include/proctal.h"
#include "cli/pattern.h"

void cli_print_proctal_error(proctal_t p);

void cli_print_pattern_error(cli_pattern cp);

void cli_print_address(void *address);

void cli_print_byte(unsigned char byte);

#endif /* CLI_PRINTER_H */

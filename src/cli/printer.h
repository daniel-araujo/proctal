#ifndef PRINTER_H
#define PRINTER_H

#include <proctal.h>

#include "pattern.h"

void cli_print_proctal_error(proctal p);

void cli_print_pattern_error(cli_pattern cp);

void cli_print_address(void *address);

void cli_print_byte(unsigned char byte);

#endif /* PRINTER_H */

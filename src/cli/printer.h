#ifndef CLI_PRINTER_H
#define CLI_PRINTER_H

#include <stdio.h>
#include "api/include/proctal.h"
#include "cli/pattern.h"

/*
 * Prints an error message 
 */
void cli_print_proctal_error(proctal_t p);

/*
 * Prints the error message of a pattern.
 */
void cli_print_pattern_error(cli_pattern cp);

/*
 * Prints a memory address.
 */
void cli_print_address(void *address);

/*
 * Prints a single byte.
 */
void cli_print_byte(unsigned char byte);

/*
 * Prints a size in bytes.
 */
void cli_print_size(size_t size);

/*
 * Prints a new line character.
 */
void cli_print_nl(void);

#endif /* CLI_PRINTER_H */

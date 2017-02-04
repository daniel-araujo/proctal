#ifndef CLI_VAL_LISt_H
#define CLI_VAL_LIST_H

#include <stdlib.h>

#include "cli/val.h"

typedef struct cli_val_list *cli_val_list;

cli_val_list cli_val_list_create(size_t size);
void cli_val_list_destroy(cli_val_list list);

size_t cli_val_list_size(cli_val_list list);

void cli_val_list_set(cli_val_list list, size_t pos, cli_val val);
cli_val cli_val_list_get(cli_val_list list, size_t pos);
void cli_val_list_del(cli_val_list list, size_t pos);

#endif /* CLI_VAL_LIST_H */

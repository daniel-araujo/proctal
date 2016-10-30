#include "cmd/val.h"

size_t proctal_cmd_val_align(enum proctal_cmd_val_type type);
size_t proctal_cmd_val_size(enum proctal_cmd_val_type type);
int proctal_cmd_val_cmp(enum proctal_cmd_val_type type, void *v1, void *v2);
void proctal_cmd_val_print(FILE *f, enum proctal_cmd_val_type type, void *value);
int proctal_cmd_val_scan(FILE *f, enum proctal_cmd_val_type type, void *value);
int proctal_cmd_val_parse(const char *s, enum proctal_cmd_val_type type, void *val);

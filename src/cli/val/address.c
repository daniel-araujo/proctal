#include "cli/val/address.h"

extern inline size_t cli_val_address_alignof(void);

extern inline size_t cli_val_address_sizeof(void);

extern inline struct cli_val_address *cli_val_address_create(void);

extern inline void cli_val_address_destroy(struct cli_val_address *v);

extern inline void *cli_val_address_data(struct cli_val_address *v);

extern inline int cli_val_address_parse_binary(struct cli_val_address *v, const char *s, size_t length);

extern inline int cli_val_address_cmp(struct cli_val_address *v, struct cli_val_address *other_v);

extern inline struct cli_val_address *cli_val_address_create_clone(struct cli_val_address *other_v);

int cli_val_address_print(struct cli_val_address *v, FILE *f)
{
	return fprintf(f, "%" PRIXPTR, v->address);
}

int cli_val_address_scan(struct cli_val_address *v, FILE *f)
{
	return fscanf(f, "%" PRIXPTR, &v->address) == 1 ? 1 : 0;
}

int cli_val_address_parse_text(struct cli_val_address *v, const char *s)
{
	return sscanf(s, "%" PRIXPTR, &v->address) == 1 ? 1 : 0;
}

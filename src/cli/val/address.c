#include "cli/val/address.h"

size_t cli_val_address_alignof(void);

size_t cli_val_address_sizeof(void);

struct cli_val_address *cli_val_address_create(void);

void cli_val_address_destroy(struct cli_val_address *v);

void *cli_val_address_raw(struct cli_val_address *v);

int cli_val_address_parse_bin(struct cli_val_address *v, const char *s, size_t length);

int cli_val_address_cmp(
	struct cli_val_address *v1,
	struct cli_val_address *v2);

int cli_val_address_print(struct cli_val_address *v, FILE *f);

int cli_val_address_scan(struct cli_val_address *v, FILE *f);

int cli_val_address_parse(struct cli_val_address *v, const char *s);

struct cli_val_address *cli_val_address_create_clone(struct cli_val_address *other_v);

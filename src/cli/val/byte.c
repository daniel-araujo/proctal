#include "cli/val/byte.h"

struct cli_val_byte *cli_val_byte_create(void);

struct cli_val_byte *cli_val_byte_create_clone(struct cli_val_byte *);

void cli_val_byte_destroy(struct cli_val_byte *v);

void *cli_val_byte_data(struct cli_val_byte *v);

int cli_val_byte_parse_bin(struct cli_val_byte *v, const char *s, size_t length);

int cli_val_byte_print(struct cli_val_byte *v, FILE *f);

int cli_val_byte_scan(struct cli_val_byte *v, FILE *f);

int cli_val_byte_parse(struct cli_val_byte *v, const char *s);

int cli_val_byte_add(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v);

int cli_val_byte_sub(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v);

int cli_val_byte_cmp(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v);

struct cli_val_byte *cli_val_byte_create_clone(struct cli_val_byte *other_v);

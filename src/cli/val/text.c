#include "text.h"

void cli_val_text_attr_init(struct cli_val_text_attr *a);

void cli_val_text_attr_set_charset(
	struct cli_val_text_attr *a,
	enum cli_val_text_charset charset);

void cli_val_text_attr_deinit(struct cli_val_text_attr *a);

struct cli_val_text *cli_val_text_create(struct cli_val_text_attr *a);

void cli_val_text_destroy(struct cli_val_text *v);

void *cli_val_text_raw(struct cli_val_text *v);

size_t cli_val_text_sizeof(struct cli_val_text *v);

int cli_val_text_parse_bin(struct cli_val_text *v, const char *s, size_t length);

int cli_val_text_print(struct cli_val_text *v, FILE *f);

int cli_val_text_scan(struct cli_val_text *v, FILE *f);

int cli_val_text_parse(struct cli_val_text *v, const char *s);

int cli_val_text_cmp(
	struct cli_val_text *v1,
	struct cli_val_text *v2);

struct cli_val_text *cli_val_text_create_clone(struct cli_val_text *other_v);

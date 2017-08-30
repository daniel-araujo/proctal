#include "cli/val/byte.h"

extern inline struct cli_val_byte *cli_val_byte_create(void);

extern inline struct cli_val_byte *cli_val_byte_create_clone(
	struct cli_val_byte *v);

extern inline void cli_val_byte_destroy(struct cli_val_byte *v);

extern inline void *cli_val_byte_data(struct cli_val_byte *v);

extern inline int cli_val_byte_parse_binary(
	struct cli_val_byte *v,
	const char *s,
	size_t length);

extern inline int cli_val_byte_print(struct cli_val_byte *v, FILE *f);

extern inline int cli_val_byte_scan(struct cli_val_byte *v, FILE *f);

extern inline int cli_val_byte_parse_text(
	struct cli_val_byte *v,
	const char *s);

extern inline int cli_val_byte_add(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v);

extern inline int cli_val_byte_sub(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v);

extern inline int cli_val_byte_cmp(
	struct cli_val_byte *v,
	struct cli_val_byte *other_v);

extern inline struct cli_val_byte *cli_val_byte_create_clone(
	struct cli_val_byte *other_v);

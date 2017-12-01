#include "cli/val/x86.h"

extern inline void cli_val_x86_attr_init(struct cli_val_x86_attr *a);

extern inline void cli_val_x86_attr_mode_set(struct cli_val_x86_attr *a, enum cli_val_x86_mode mode);

extern inline void cli_val_x86_attr_syntax_set(struct cli_val_x86_attr *a, enum cli_val_x86_syntax syntax);

extern inline void cli_val_x86_attr_deinit(struct cli_val_x86_attr *a);

extern inline struct cli_val_x86 *cli_val_x86_create(struct cli_val_x86_attr *a);

extern inline void cli_val_x86_destroy(struct cli_val_x86 *v);

extern inline void cli_val_x86_address_set(struct cli_val_x86 *v, void *address);

extern inline void *cli_val_x86_address(struct cli_val_x86 *v);

extern inline void *cli_val_x86_data(struct cli_val_x86 *v);

extern inline size_t cli_val_x86_sizeof(struct cli_val_x86 *v);

extern inline struct cli_val_x86 *cli_val_x86_create_clone(struct cli_val_x86 *other_v);

extern inline int cli_val_x86_print(struct cli_val_x86 *v, FILE *f);

extern inline int cli_val_x86_parse_binary(struct cli_val_x86 *v, const void *b, size_t length);

extern inline int cli_val_x86_parse_text(struct cli_val_x86 *v, const char *s);

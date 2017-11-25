#include "cli/val/mips.h"

extern inline void cli_val_mips_attr_init(struct cli_val_mips_attr *a);

extern inline void cli_val_mips_attr_mode_set(struct cli_val_mips_attr *a, enum cli_val_mips_mode mode);

extern inline void cli_val_mips_attr_endianness_set(struct cli_val_mips_attr *a, enum cli_val_mips_endianness endianness);

extern inline void cli_val_mips_attr_deinit(struct cli_val_mips_attr *a);

extern inline struct cli_val_mips *cli_val_mips_create(struct cli_val_mips_attr *a);

extern inline void cli_val_mips_destroy(struct cli_val_mips *v);

extern inline void cli_val_mips_address_set(struct cli_val_mips *v, void *address);

extern inline void *cli_val_mips_address(struct cli_val_mips *v);

extern inline void *cli_val_mips_data(struct cli_val_mips *v);

extern inline size_t cli_val_mips_sizeof(struct cli_val_mips *v);

extern inline struct cli_val_mips *cli_val_mips_create_clone(struct cli_val_mips *other_v);

extern inline int cli_val_mips_print(struct cli_val_mips *v, FILE *f);

extern inline int cli_val_mips_parse_binary(struct cli_val_mips *v, const char *s, size_t length);

extern inline int cli_val_mips_parse_text(struct cli_val_mips *v, const char *s);

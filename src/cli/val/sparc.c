#include "cli/val/sparc.h"

extern inline void cli_val_sparc_attr_init(struct cli_val_sparc_attr *a);

extern inline void cli_val_sparc_attr_mode_set(struct cli_val_sparc_attr *a, enum cli_val_sparc_mode mode);

extern inline void cli_val_sparc_attr_endianness_set(struct cli_val_sparc_attr *a, enum cli_val_sparc_endianness endianness);

extern inline void cli_val_sparc_attr_deinit(struct cli_val_sparc_attr *a);

extern inline struct cli_val_sparc *cli_val_sparc_create(struct cli_val_sparc_attr *a);

extern inline void cli_val_sparc_destroy(struct cli_val_sparc *v);

extern inline void cli_val_sparc_address_set(struct cli_val_sparc *v, void *address);

extern inline void *cli_val_sparc_address(struct cli_val_sparc *v);

extern inline void *cli_val_sparc_data(struct cli_val_sparc *v);

extern inline size_t cli_val_sparc_sizeof(struct cli_val_sparc *v);

extern inline struct cli_val_sparc *cli_val_sparc_create_clone(struct cli_val_sparc *other_v);

extern inline int cli_val_sparc_print(struct cli_val_sparc *v, FILE *f);

extern inline int cli_val_sparc_parse_binary(struct cli_val_sparc *v, const char *s, size_t length);

extern inline int cli_val_sparc_parse_text(struct cli_val_sparc *v, const char *s);

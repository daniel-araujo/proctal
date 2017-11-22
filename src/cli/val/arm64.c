#include "cli/val/arm64.h"

extern inline void cli_val_arm64_attr_init(struct cli_val_arm64_attr *a);

extern inline void cli_val_arm64_attr_deinit(struct cli_val_arm64_attr *a);

extern inline struct cli_val_arm64 *cli_val_arm64_create(struct cli_val_arm64_attr *a);

extern inline void cli_val_arm64_destroy(struct cli_val_arm64 *v);

extern inline void cli_val_arm64_address_set(struct cli_val_arm64 *v, void *address);

extern inline void *cli_val_arm64_address(struct cli_val_arm64 *v);

extern inline void *cli_val_arm64_data(struct cli_val_arm64 *v);

extern inline size_t cli_val_arm64_sizeof(struct cli_val_arm64 *v);

extern inline struct cli_val_arm64 *cli_val_arm64_create_clone(struct cli_val_arm64 *other_v);

extern inline int cli_val_arm64_print(struct cli_val_arm64 *v, FILE *f);

extern inline int cli_val_arm64_parse_binary(struct cli_val_arm64 *v, const char *s, size_t length);

extern inline int cli_val_arm64_parse_text(struct cli_val_arm64 *v, const char *s);

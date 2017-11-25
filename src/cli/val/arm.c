#include "cli/val/arm.h"

extern inline void cli_val_arm_attr_init(struct cli_val_arm_attr *a);

extern inline void cli_val_arm_attr_mode_set(struct cli_val_arm_attr *a, enum cli_val_arm_mode mode);

extern inline void cli_val_arm_attr_endianness_set(struct cli_val_arm_attr *a, enum cli_val_arm_endianness endianness);

extern inline void cli_val_arm_attr_deinit(struct cli_val_arm_attr *a);

extern inline struct cli_val_arm *cli_val_arm_create(struct cli_val_arm_attr *a);

extern inline void cli_val_arm_destroy(struct cli_val_arm *v);

extern inline void cli_val_arm_address_set(struct cli_val_arm *v, void *address);

extern inline void *cli_val_arm_address(struct cli_val_arm *v);

extern inline void *cli_val_arm_data(struct cli_val_arm *v);

extern inline size_t cli_val_arm_sizeof(struct cli_val_arm *v);

extern inline struct cli_val_arm *cli_val_arm_create_clone(struct cli_val_arm *other_v);

extern inline int cli_val_arm_print(struct cli_val_arm *v, FILE *f);

extern inline int cli_val_arm_parse_binary(struct cli_val_arm *v, const char *s, size_t length);

extern inline int cli_val_arm_parse_text(struct cli_val_arm *v, const char *s);

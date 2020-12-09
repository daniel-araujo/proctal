#include "cli/vmagazine.h"

extern inline enum vmagazine_result vmagazine_init(struct vmagazine *this);

extern inline void vmagazine_deinit(struct vmagazine *this);

extern inline void vmagazine_template_address_set(struct vmagazine *this, void *address);

extern inline void vmagazine_template_value_set(struct vmagazine *this, cli_val_t value);

extern inline size_t vmagazine_size(struct vmagazine *this);

extern inline cli_val_t *vmagazine_value(struct vmagazine *this, size_t index);

extern inline enum vmagazine_result vmagazine_parse_text(struct vmagazine *this, const char *str, size_t length);

extern inline enum vmagazine_result vmagazine_parse_binary(struct vmagazine *this, const void *binary, size_t size, size_t *read);

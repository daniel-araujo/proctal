#include "harr/harr.h"

size_t harr_data_index(struct harr *h, int i);

void harr_init(struct harr *h, size_t item_size);

void harr_deinit(struct harr *h);

int harr_size(struct harr *h);

int harr_resize(struct harr *h, size_t size);

void *harr_raw(struct harr *h, int i);

void harr_get(struct harr *h, int i, void *v);

void harr_set(struct harr *h, int i, void *v);

#ifndef LIB_PROCTAL_IMPL_H
#define LIB_PROCTAL_IMPL_H

/*
 * These are the functions that an implementation must define.
 */

proctal_t proctal_impl_create(void);

void proctal_impl_destroy(proctal_t p);

void proctal_impl_set_pid(proctal_t p, int pid);

int proctal_impl_pid(proctal_t p);

size_t proctal_impl_read(proctal_t p, void *addr, char *out, size_t size);

size_t proctal_impl_write(proctal_t p, void *addr, const char *in, size_t size);

int proctal_impl_freeze(proctal_t p);

int proctal_impl_unfreeze(proctal_t p);

void proctal_impl_address_new(proctal_t p);

int proctal_impl_address(proctal_t p, void **addr);

void proctal_impl_region_new(proctal_t p);

int proctal_impl_region(proctal_t p, void **start, void **end);

int proctal_impl_watch(proctal_t p, void **addr);

int proctal_impl_execute(proctal_t p, const char *byte_code, size_t byte_code_length);

void *proctal_impl_alloc(proctal_t p, size_t size, int perm);

void proctal_impl_dealloc(proctal_t p, void *addr);

#endif /* LIB_PROCTAL_IMPL_H */

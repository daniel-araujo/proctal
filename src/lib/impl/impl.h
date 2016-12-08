#ifndef PROCTAL_IMPL_H
#define PROCTAL_IMPL_H

/*
 * These are the functions that an implementation must define.
 */

proctal proctal_impl_create(void);

void proctal_impl_destroy(proctal p);

void proctal_impl_set_pid(proctal p, int pid);

int proctal_impl_pid(proctal p);

size_t proctal_impl_read(proctal p, void *addr, char *out, size_t size);

size_t proctal_impl_write(proctal p, void *addr, const char *in, size_t size);

int proctal_impl_freeze(proctal p);

int proctal_impl_unfreeze(proctal p);

void proctal_impl_address_new(proctal p);

int proctal_impl_address(proctal p, void **addr);

int proctal_impl_watch(proctal p, void **addr);

int proctal_impl_execute(proctal p, const char *byte_code, size_t byte_code_length);

void *proctal_impl_alloc(proctal p, size_t size, int perm);

void proctal_impl_dealloc(proctal p, void *addr);

#endif /* PROCTAL_IMPL_H */

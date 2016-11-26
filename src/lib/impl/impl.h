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

proctal_addr_iter proctal_impl_addr_iter_create(proctal p);

void proctal_impl_addr_iter_destroy(proctal_addr_iter iter);

int proctal_impl_addr_iter_first(proctal_addr_iter iter);

int proctal_impl_addr_iter_next(proctal_addr_iter iter);

proctal_watch proctal_impl_watch_create(proctal p);

void proctal_impl_watch_destroy(proctal_watch pw);

int proctal_impl_watch_next(proctal_watch pw, void **addr);

int proctal_impl_execute(proctal p, const char *byte_code, size_t byte_code_length);

#endif /* PROCTAL_IMPL_H */

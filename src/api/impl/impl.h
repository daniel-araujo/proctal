#ifndef API_PROCTAL_IMPL_H
#define API_PROCTAL_IMPL_H

/*
 * These are the functions that an implementation must define.
 */

proctal_t proctal_impl_open(void);

void proctal_impl_close(proctal_t p);

void proctal_impl_pid_set(proctal_t p, int pid);

int proctal_impl_pid(proctal_t p);

size_t proctal_impl_read(proctal_t p, void *addr, char *out, size_t size);

size_t proctal_impl_write(proctal_t p, void *addr, const char *in, size_t size);

int proctal_impl_freeze(proctal_t p);

int proctal_impl_unfreeze(proctal_t p);

void proctal_impl_scan_address_start(proctal_t p);

void proctal_impl_scan_address_stop(proctal_t p);

int proctal_impl_scan_address(proctal_t p, void **addr);

void proctal_impl_scan_region_start(proctal_t p);

void proctal_impl_scan_region_stop(proctal_t p);

int proctal_impl_scan_region(proctal_t p, void **start, void **end);

int proctal_impl_watch_start(proctal_t p);

void proctal_impl_watch_stop(proctal_t p);

int proctal_impl_watch(proctal_t p, void **addr);

int proctal_impl_execute(proctal_t p, const char *bytecode, size_t bytecode_length);

void *proctal_impl_allocate(proctal_t p, size_t size, int perm);

void proctal_impl_deallocate(proctal_t p, void *addr);

#endif /* API_PROCTAL_IMPL_H */

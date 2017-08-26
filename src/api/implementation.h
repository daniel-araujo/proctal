#ifndef API_IMPLEMENTATION_H
#define API_IMPLEMENTATION_H

/*
 * These are the functions that an implementation must define.
 */

struct proctal *proctal_implementation_open(void);

void proctal_implementation_close(struct proctal *p);

void proctal_implementation_pid_set(struct proctal *p, int pid);

int proctal_implementation_pid(struct proctal *p);

size_t proctal_implementation_read(struct proctal *p, void *addr, char *out, size_t size);

size_t proctal_implementation_write(struct proctal *p, void *addr, const char *in, size_t size);

void proctal_implementation_freeze(struct proctal *p);

void proctal_implementation_unfreeze(struct proctal *p);

void proctal_implementation_scan_address_start(struct proctal *p);

void proctal_implementation_scan_address_stop(struct proctal *p);

int proctal_implementation_scan_address_next(struct proctal *p, void **addr);

void proctal_implementation_scan_region_start(struct proctal *p);

void proctal_implementation_scan_region_stop(struct proctal *p);

int proctal_implementation_scan_region_next(struct proctal *p, void **start, void **end);

void proctal_implementation_watch_start(struct proctal *p);

void proctal_implementation_watch_stop(struct proctal *p);

int proctal_implementation_watch_next(struct proctal *p, void **addr);

void proctal_implementation_execute(struct proctal *p, const char *bytecode, size_t bytecode_length);

void *proctal_implementation_allocate(struct proctal *p, size_t size);

void proctal_implementation_deallocate(struct proctal *p, void *addr);

#endif /* API_IMPLEMENTATION_H */

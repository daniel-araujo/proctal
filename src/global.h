#ifndef GLOBAL_H
#define GLOBAL_H

void *(*proctal_global_malloc())(size_t);
void (*proctal_global_free())(void *);

#endif /* GLOBAL_H */

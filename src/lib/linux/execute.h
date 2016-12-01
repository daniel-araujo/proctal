#ifndef LINUX_EXECUTE_H
#define LINUX_EXECUTE_H

#include <linux/proctal.h>

int proctal_linux_execute(struct proctal_linux *pl, const char *byte_code, size_t byte_code_length);

#endif /* LINUX_EXECUTE_H */

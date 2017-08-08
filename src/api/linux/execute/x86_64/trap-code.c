#include <stddef.h>

#include "magic/magic.h"

const char proctal_linux_execute_implementation_trap_code[] = {
	// It's a trap.
	0xcd, 0x03,
};

const size_t proctal_linux_execute_implementation_trap_code_size = ARRAY_SIZE(proctal_linux_execute_implementation_trap_code);

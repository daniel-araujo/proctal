#include <stddef.h>

#include "magic/magic.h"

const char proctal_linux_execute_implementation_no_op_code[] = {
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
};

const size_t proctal_linux_execute_implementation_no_op_code_size = ARRAY_SIZE(proctal_linux_execute_implementation_no_op_code);

#include "lib/proctal.h"

int proctal_execute(proctal_t p, const char *byte_code, size_t byte_code_length)
{
	return proctal_impl_execute(p, byte_code, byte_code_length);
}

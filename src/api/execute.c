#include "api/proctal.h"

int proctal_execute(proctal_t p, const char *bytecode, size_t bytecode_length)
{
	return proctal_impl_execute(p, bytecode, bytecode_length);
}

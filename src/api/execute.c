#include "api/proctal.h"
#include "api/implementation.h"

int proctal_execute(proctal_t p, const char *bytecode, size_t bytecode_length)
{
	return proctal_implementation_execute(p, bytecode, bytecode_length);
}

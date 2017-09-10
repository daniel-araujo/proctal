#include "api/proctal.h"
#include "api/implementation.h"

void proctal_execute(struct proctal *p, const void *bytecode, size_t bytecode_length)
{
	proctal_implementation_execute(p, bytecode, bytecode_length);
}

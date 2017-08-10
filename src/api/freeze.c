#include "api/proctal.h"
#include "api/implementation.h"

void proctal_freeze(proctal_t p)
{
	proctal_implementation_freeze(p);
}

void proctal_unfreeze(proctal_t p)
{
	proctal_implementation_unfreeze(p);
}

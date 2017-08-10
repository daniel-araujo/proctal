#include "api/proctal.h"
#include "api/implementation.h"

int proctal_freeze(proctal_t p)
{
	return proctal_implementation_freeze(p);
}

int proctal_unfreeze(proctal_t p)
{
	return proctal_implementation_unfreeze(p);
}

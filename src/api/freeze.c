#include "api/proctal.h"
#include "api/implementation.h"

void proctal_freeze(struct proctal *p)
{
	proctal_implementation_freeze(p);
}

void proctal_unfreeze(struct proctal *p)
{
	proctal_implementation_unfreeze(p);
}

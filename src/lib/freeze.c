#include "lib/proctal.h"

int proctal_freeze(proctal_t p)
{
	return proctal_impl_freeze(p);
}

int proctal_unfreeze(proctal_t p)
{
	return proctal_impl_unfreeze(p);
}

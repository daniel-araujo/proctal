#include "lib/proctal.h"

int proctal_freeze(proctal p)
{
	return proctal_impl_freeze(p);
}

int proctal_unfreeze(proctal p)
{
	return proctal_impl_unfreeze(p);
}

#include "api/proctal.h"
#include "api/implementation.h"

void proctal_pause(struct proctal *p)
{
	proctal_implementation_pause(p);
}

void proctal_resume(struct proctal *p)
{
	proctal_implementation_resume(p);
}

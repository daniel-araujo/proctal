#include "pq/pq.h"
#include "pq/implementation.h"
#include "pq/quit-state.h"

int pq_start(void)
{
	pq_quit_state_set(0);

	return pq_implementation_start();
}

int pq_wait(void)
{
	if (pq_check()) {
		return 1;
	}

	return pq_implementation_wait();
}

int pq_check(void)
{
	return pq_quit_state();
}

int pq_stop(void)
{
	return pq_implementation_stop();
}

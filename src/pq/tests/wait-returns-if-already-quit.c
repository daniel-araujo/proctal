#include <assert.h>
#include <signal.h>

#include "pq/pq.h"

/*
 * Checks that pq_wait returns right away instead of blocking when a
 * quit request was already received before it was called.
 */
int main(void)
{
	assert(pq_start());

	raise(SIGINT);

	assert(pq_wait());

	assert(pq_stop());
}

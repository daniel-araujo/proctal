#include <assert.h>

#include "pq/pq.h"

/*
 * Checks that pq_check reports no pending quit request right after
 * pq_start, before any signal has been received.
 */
int main(void)
{
	assert(pq_start());

	assert(pq_check() == 0);

	assert(pq_stop());
}

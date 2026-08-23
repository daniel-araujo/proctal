#include <assert.h>
#include <signal.h>

#include "pq/pq.h"

/*
 * Checks that receiving SIGTERM after pq_start makes pq_check report a
 * pending quit request.
 */
int main(void)
{
	assert(pq_start());

	raise(SIGTERM);

	assert(pq_check() == 1);

	assert(pq_stop());
}

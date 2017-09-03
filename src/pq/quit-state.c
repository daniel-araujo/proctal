#include "pq/quit-state.h"

static int quit_state = 0;

void pq_quit_state_set(int state)
{
	quit_state = !!state;
}

int pq_quit_state(void)
{
	return quit_state;
}

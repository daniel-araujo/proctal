#include <windows.h>
#include <signal.h>
#include <unistd.h>

#include "pq/implementation.h"
#include "pq/quit-state.h"

static void quit(int signum)
{
	pq_quit_state_set(1);
}

int pq_implementation_start(void)
{
	signal(SIGINT, quit);
	signal(SIGTERM, quit);

	return 1;
}

int pq_implementation_stop(void)
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	return 1;
}

int pq_implementation_wait(void)
{
	while (!pq_quit_state()) {
		// With no support for sigsuspend or pause, this is the
		// quickest workaround.
		Sleep(33);
	}

	return 1;
}

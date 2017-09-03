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
	struct sigaction sa = {
		.sa_handler = quit,
		.sa_flags = 0,
	};

	sigemptyset(&sa.sa_mask);

	return sigaction(SIGINT, &sa, NULL) != -1
		&& sigaction(SIGTERM, &sa, NULL) != -1;
}

int pq_implementation_stop(void)
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	return 1;
}

int pq_implementation_wait(void)
{
	sigset_t mask, oldmask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	while (!pq_quit_state()) {
		sigsuspend(&oldmask);
	}

	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	return 1;
}

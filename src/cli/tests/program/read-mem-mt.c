#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

static void *t2_fun(void *arg)
{
	volatile unsigned long long var = 1;

	setvbuf(stdout, NULL, _IONBF, 0);

	fprintf(stdout, "%p\n", &var);

	for (; var;) {
	}

	return NULL;
}

int main(void)
{
	pthread_t t2;

	pthread_create(&t2, NULL, t2_fun, NULL);

	pthread_join(t2, NULL);
}

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

static void *t2_fun(void *arg)
{
	char buf[1];

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	for (;;) {
		size_t read = fread(buf, 1, sizeof(buf), stdin);

		if (read) {
			fwrite(buf, 1, read, stdout);
		}

		if (feof(stdin)) {
			return NULL;
		}
	}
}

int main(void)
{
	pthread_t t2;

	pthread_create(&t2, NULL, t2_fun, NULL);

	pthread_join(t2, NULL);
}

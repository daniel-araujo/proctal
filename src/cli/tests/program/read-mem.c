#include <stdlib.h>
#include <stdio.h>

int main(void)
{
	volatile unsigned long long var = 1;

	setvbuf(stdout, NULL, _IONBF, 0);

	fprintf(stdout, "%p\n", &var);

	for (; var;) {
	}
}

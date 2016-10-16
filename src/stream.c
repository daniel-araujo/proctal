#include <stdlib.h>

struct proctal_stream {
	void *base;
	void *current;
	int length;
};

typedef struct proctal_stream *proctal_stream;

proctal_stream proctal_stream_create(char *buffer, int length)
{
	proctal_stream stream = (proctal_stream) malloc(sizeof *stream);

	if (stream == NULL) {
		return NULL;
	}

	stream->base = buffer;
	stream->current = stream->base;
	stream->length = length;

	return stream;
}

void proctal_stream_destroy(proctal_stream stream)
{
	free(stream);
}

#ifndef PROCTAL_H
#define PROCTAL_H

struct proctal_process;
struct proctal_stream;
struct proctal_process_memory_address { void *cant_touch_this; };

typedef struct proctal_process *proctal_process;
typedef struct proctal_process_memory_address proctal_process_memory_address;
typedef struct proctal_stream *proctal_stream;

/*
 * Reads from a process' memory.
 */
proctal_stream proctal_read_memory(
	proctal_process process,
	proctal_process_memory_address addr,
	int size);

/*
 * Reads an int from a process' memory.
 */
int proctal_read_memory_int(
	proctal_process process,
	proctal_process_memory_address addr);

/*
 * Writes to a process' memory.
 */
void proctal_write_memory(
	proctal_process process,
	proctal_process_memory_address addr,
	proctal_stream stream);

/*
 * Writes an int to a process' memory.
 */
void proctal_write_memory_int(
	proctal_process process,
	proctal_process_memory_address addr,
	int val);

/*
 * Creates a representation of a process.
 */
proctal_process proctal_process_create(int pid);

int proctal_process_get_pid(proctal_process process);

void proctal_process_destroy(proctal_process process);

/*
 * Creates a representation of a process' memory address.
 */
proctal_process_memory_address proctal_process_memory_address_create(
	proctal_process process,
	void *addr);

long proctal_process_memory_address_get_offset(proctal_process_memory_address address);

/*
 * Creates a representation of a stream of characters.
 */
proctal_stream proctal_stream_create(
	char *buffer,
	int length);

#endif /* PROCTAL_H */

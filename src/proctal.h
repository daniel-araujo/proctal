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
proctal_stream proctal_read_memory(proctal_process process, proctal_process_memory_address addr);

/*
 * Writes to a process' memory.
 */
void proctal_write_memory(proctal_process *process, proctal_process_memory_address *addr, proctal_stream *stream);

#endif /* PROCTAL_H */

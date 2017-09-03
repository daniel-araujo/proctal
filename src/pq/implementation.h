#ifndef PQ_IMPLEMENTATION_H
#define PQ_IMPLEMENTATION_H

/*
 * Starts keeping track of messages and signals.
 *
 * Returns 1 on success and 0 on failure.
 */
int pq_implementation_start(void);

/*
 * Stops tracking.
 *
 * Returns 1 on success and 0 on failure.
 */
int pq_implementation_stop(void);

/*
 * Waits until the process receives a message that it wants to quit.
 *
 * Returns 1 on success and 0 on failure.
 */
int pq_implementation_wait(void);

#endif /* PQ_IMPLEMENTATION_H */

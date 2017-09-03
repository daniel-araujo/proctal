#ifndef PQ_PQ_H
#define PQ_PQ_H

/*
 * Starts keeping track of messages and signals.
 *
 * Returns 1 on success and 0 on failure.
 */
int pq_start(void);

/*
 * Stops tracking.
 *
 * Returns 1 on success and 0 on failure.
 */
int pq_stop(void);

/*
 * Waits until the process receives a message that it wants to quit.
 *
 * This function can only be called while keeping track of messages and
 * signals.
 *
 * Returns 1 on success and 0 on failure.
 */
int pq_wait(void);

/*
 * Checks whether the process received a message to quit.
 *
 * This function can be called after having stopped tracking for messages and
 * signals.
 *
 * Returns 1 if yes and 0 if not.
 */
int pq_check(void);

#endif /* PQ_PQ_H */

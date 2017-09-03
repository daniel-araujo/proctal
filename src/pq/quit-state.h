#ifndef PQ_QUIT_STATE_H
#define PQ_QUIT_STATE_H

/*
 * Lets you set whether to want to quit.
 *
 * 1 means yes, 0 means no.
 */
void pq_quit_state_set(int state);

/*
 * Whether you want to quit.
 *
 * 1 means yes, 0 means no.
 */
int pq_quit_state(void);

#endif /* PQ_QUIT_STATE_H */

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <darr.h>

#include "cli/cmd/watch.h"
#include "cli/printer.h"
#include "api/include/proctal.h"
#include "magic/magic.h"
#include "pq/pq.h"

/*
 * Tracks addresses that matched.
 */
struct matches {
	// Actual storage for addresses.
	struct darr addresses;

	// Number of addresses stored.
	size_t count;
};

#define MATCHES_ERROR_OUT_OF_MEMORY 1

/*
 * Initializes the structure that keeps track of addresses.
 *
 * Returns 0 on success, an error code on failure.
 */
static inline int matches_init(struct matches *matches)
{
	matches->count = 0;

	darr_init(&matches->addresses, sizeof(void *));

	if (!darr_resize(&matches->addresses, 42)) {
		darr_deinit(&matches->addresses);
		return MATCHES_ERROR_OUT_OF_MEMORY;
	}

	return 0;
}

/*
 * Deinitializes the structure.
 */
static inline void matches_deinit(struct matches *matches)
{
	darr_deinit(&matches->addresses);
}

/*
 * Checks whether the given address has already been seen.
 */
static inline int matches_contains(struct matches *matches, void *address)
{
	// TODO: Should use a data structure with better look up performance.

	for (size_t i = 0; i < matches->count; ++i) {
		void **candidate = darr_element(&matches->addresses, i);

		if (address == *candidate) {
			return 1;
		}
	}

	return 0;
}

/*
 * Marks an address as seen.
 *
 * Returns 0 on success, an error code on failure.
 */
static inline int matches_register(struct matches *matches, void *address)
{
	matches->count += 1;

	if (matches->count > darr_size(&matches->addresses)) {
		// We're out of space. Let's double it.
		if (!darr_grow(&matches->addresses, matches->count)) {
			return MATCHES_ERROR_OUT_OF_MEMORY;
		}
	}

	void **e = darr_element(&matches->addresses, matches->count - 1);
	*e = address;

	return 0;
}

/*
 * Handles an error from matches.
 *
 * Returns 1 when handled, 0 when nothing done.
 */
static inline int handle_matches_error(int code)
{
	switch (code) {
	case 0:
		return 0;

	case MATCHES_ERROR_OUT_OF_MEMORY:
		fprintf(stderr, "Out of memory.\n");
		return 1;

	default:
		fprintf(stderr, "Unexpected failure.\n");
		return 1;
	}
}

int cli_cmd_watch(struct cli_cmd_watch_arg *arg)
{
	int ret = 1;

	if (!pq_start()) {
		fprintf(stderr, "Failed to start tracking quit signals.\n");
		goto exit0;
	}

	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit2;
	}

	if (!arg->read && !arg->write && !arg->execute) {
		fprintf(stderr, "Did not specify what to watch for.\n");
		goto exit2;
	}

	if (!(arg->read && arg->write && !arg->execute)
		&& !(arg->write && !arg->read && !arg->execute)
		&& !(!arg->write && !arg->read && arg->execute)) {
		fprintf(stderr, "The given combination of read, write and execute options is not supported.\n");
		goto exit2;
	}

	proctal_pid_set(p, arg->pid);

	proctal_watch_address_set(p, arg->address);
	proctal_watch_read_set(p, arg->read);
	proctal_watch_write_set(p, arg->write);
	proctal_watch_execute_set(p, arg->execute);

	struct matches matches;
	if (arg->unique) {
		if (handle_matches_error(matches_init(&matches))) {
			goto exit2;
		}
	}

	proctal_watch_start(p);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit3;
	}

	void *address_start = arg->address_start;
	void *address_stop = arg->address_stop == NULL ? (char *) ~((uintptr_t) 0) : arg->address_stop;

	while (!pq_check()) {
		void *address;

		if (!proctal_watch_next(p, &address)) {
			switch (proctal_error(p)) {
			case 0:
				continue;

			case PROCTAL_ERROR_INTERRUPT:
				if (!proctal_error_recover(p)) {
					goto exit4;
				}
				continue;

			default:
				cli_print_proctal_error(p);
				goto exit4;
			}
		}

		if (address < address_start || address >= address_stop) {
			// Out of range.
			continue;
		}

		if (arg->unique) {
			if (matches_contains(&matches, address)) {
				continue;
			} else {
				if (handle_matches_error(matches_register(&matches, address))) {
					goto exit4;
				}
			}
		}

		cli_print_address(address);
		printf("\n");
	}

	ret = 0;
exit4:
	proctal_watch_stop(p);
exit3:
	if (arg->unique) {
		matches_deinit(&matches);
	}
exit2:
	proctal_close(p);
exit1:
	pq_stop();
exit0:
	return ret;
}

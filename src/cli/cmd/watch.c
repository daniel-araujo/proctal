#include <stdio.h>
#include <assert.h>
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

/*
 * Initializes the structure that keeps track of addresses.
 *
 * Returns 0 on success, 1 when out of memory.
 */
static inline int matches_init(struct matches *matches)
{
	darr_init(&matches->addresses, sizeof(void *));

	if (!darr_resize(&matches->addresses, 42)) {
		darr_deinit(&matches->addresses);
		return 1;
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
			return 0;
		}
	}

	return 1;
}

/*
 * Marks an address as seen.
 *
 * Returns 0 on success, 1 when out of memory.
 */
static inline int matches_register(struct matches *matches, void *address)
{
	matches->count += 1;

	if (matches->count > darr_size(&matches->addresses)) {
		// We're out of space. Let's double it.
		if (!darr_grow(&matches->addresses, matches->count)) {
			return 1;
		}
	}

	void **e = darr_element(&matches->addresses, matches->count - 1);
	*e = address;

	return 0;
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
		switch (matches_init(&matches)) {
		case 0:
			break;

		case 1:
			fprintf(stderr, "Out of memory.\n");
			goto exit2;

		default:
			fprintf(stderr, "Unexpected failure.\n");
			goto exit2;
		}
	}

	proctal_watch_start(p);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit3;
	}

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

		if (arg->unique) {
			if (matches_contains(&matches, address)) {
				continue;
			} else {
				switch (matches_register(&matches, address)) {
				case 0:
					break;

				case 1:
					fprintf(stderr, "Out of memory.\n");
					goto exit4;

				default:
					fprintf(stderr, "Unexpected failure.\n");
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

#ifndef LINUX_ADDR_H
#define LINUX_ADDR_H

#include <stdio.h>

#include <linux/proctal.h>
#include <linux/proc.h>

struct proctal_linux_addr_iter {
	// Base structure.
	struct proctal_addr_iter iter;

	// Proctal instance that this iterator belongs to.
	struct proctal_linux *pl;

	// Memory mappings of the address space.
	FILE *maps;

	// Current region being read.
	struct proctal_linux_mem_region region;
};

void proctal_linux_addr_iter_init(struct proctal_linux *pl, struct proctal_linux_addr_iter *iterl);

void proctal_linux_addr_iter_deinit(struct proctal_linux *pl, struct proctal_linux_addr_iter *iterl);

int proctal_linux_addr_iter_first(struct proctal_linux_addr_iter *iterl);

int proctal_linux_addr_iter_next(struct proctal_linux_addr_iter *iterl);

#endif /* LINUX_ADDR_H */

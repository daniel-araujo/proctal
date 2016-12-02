#include <proctal.h>
#include <linux/proctal.h>
#include <linux/mem.h>
#include <linux/ptrace.h>
#include <linux/addr.h>
#include <linux/watch.h>
#include <linux/alloc.h>
#include <linux/execute.h>

proctal proctal_impl_create(void)
{
	struct proctal_linux *pl = proctal_global_malloc(sizeof *pl);

	if (pl == NULL) {
		return NULL;
	}

	proctal_linux_init(pl);

	return (proctal) pl;
}

void proctal_impl_destroy(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	if (pl == NULL) {
		return;
	}

	proctal_linux_deinit(pl);

	proctal_global_free(pl);
}

void proctal_impl_set_pid(proctal p, int pid)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_set_pid(pl, (pid_t) pid);
}

int proctal_impl_pid(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return (int) proctal_linux_pid(pl);
}

size_t proctal_impl_read(proctal p, void *addr, char *out, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_mem_read(pl, addr, out, size);
}

size_t proctal_impl_write(proctal p, void *addr, const char *in, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_mem_write(pl, addr, in, size);
}

int proctal_impl_freeze(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_ptrace_attach(pl);
}

int proctal_impl_unfreeze(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_ptrace_detach(pl);
}

proctal_addr_iter proctal_impl_addr_iter_create(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;
	struct proctal_linux_addr_iter *iterl = proctal_malloc(p, sizeof *iterl);

	if (iterl == NULL) {
		return NULL;
	}

	proctal_linux_addr_iter_init(pl, iterl);

	return (proctal_addr_iter) iterl;
}

void proctal_impl_addr_iter_destroy(proctal_addr_iter iter)
{
	struct proctal_linux_addr_iter *iterl = (struct proctal_linux_addr_iter *) iter;

	proctal_linux_addr_iter_deinit(iterl->pl, iterl);

	proctal_free(&iterl->pl->p, iterl);
}

int proctal_impl_addr_iter_first(proctal_addr_iter iter)
{
	struct proctal_linux_addr_iter *iterl = (struct proctal_linux_addr_iter *) iter;

	return proctal_linux_addr_iter_first(iterl);
}

int proctal_impl_addr_iter_next(proctal_addr_iter iter)
{
	struct proctal_linux_addr_iter *iterl = (struct proctal_linux_addr_iter *) iter;

	return proctal_linux_addr_iter_next(iterl);
}

proctal_watch proctal_impl_watch_create(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;
	struct proctal_linux_watch *plw = proctal_malloc(p, sizeof *plw);

	if (plw == NULL) {
		return NULL;
	}

	proctal_linux_watch_init(pl, plw);

	return (proctal_watch) plw;
}

void proctal_impl_watch_destroy(proctal_watch pw)
{
	struct proctal_linux_watch *plw = (struct proctal_linux_watch *) pw;

	proctal_linux_watch_deinit(plw->pl, plw);

	proctal_free(&plw->pl->p, plw);
}

int proctal_impl_watch_next(proctal_watch pw, void **addr)
{
	struct proctal_linux_watch *plw = (struct proctal_linux_watch *) pw;

	return proctal_linux_watch_next(plw, addr);
}

int proctal_impl_execute(proctal p, const char *byte_code, size_t byte_code_length)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_execute(pl, byte_code, byte_code_length);
}

void *proctal_impl_alloc(proctal p, size_t size, int perm)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_alloc(pl, size, perm);
}

void proctal_impl_dealloc(proctal p, void *addr)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_dealloc(pl, addr);
}

/*
 * Scheduler proxy of NUSE for rumpuser backend
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <rump/rumpuser_port.h>
#include <rump/rumpuser.h>

#include "sim-init.h"
#include "sim-assert.h"
#include "sim.h"
#include "nuse.h"
#include "nuse-sched.h"

extern struct SimExported *g_exported;
struct NuseTask *lwp0 = NULL;

struct NuseTask *nuse_new_task(char *name)
{
	struct NuseTask *task;

	task = malloc(sizeof(struct NuseTask));
	memset(task, 0, sizeof(*task));
	task->s_task = g_exported->task_create(task, getpid());
	strncpy(task->name, name, strlen(name));
	rumpuser_cv_init(&task->cv);
	rumpuser_mutex_init(&task->mtx, RUMPUSER_MTX_SPIN);

	return task;
}

void nuse_release_task(struct NuseTask *task)
{
	g_exported->task_destroy(task->s_task);
	rumpuser_cv_destroy(task->cv);
#ifdef notyet
	rumpuser_mutex_destroy(task->mtx);
#endif
	free(task->mtx);
	free(task);
	rumpuser_thread_exit();
}

struct SimTask *nuse_task_current(struct SimKernel *kernel)

{
	struct NuseTask *task = (struct NuseTask *)rumpuser_curlwp();

	if (!lwp0) {
		lwp0 = nuse_new_task("init");
		rumpuser_curlwpop(RUMPUSER_LWP_CREATE, (struct lwp *)lwp0);
	}

	if (!task) {
#if 1
		task = lwp0;
		rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)task);
#else
		task = nuse_new_task("auto");
		rumpuser_curlwpop(RUMPUSER_LWP_CREATE, (struct lwp *)task);
		rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)task);
#endif
	}

	return task->s_task;
}

struct thrdesc {
	void (*f)(void *);
	void *arg;
	struct NuseTask *newlwp;
	int runnable;
	struct timespec timeout;
};

static void *nuse_task_start_trampoline(void *arg)
{
	struct thrdesc *td = arg;
	struct NuseTask *task = td->newlwp;
	void (*f)(void *);
	void *thrarg;
	int err;

	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)task);

	f = td->f;
	thrarg = td->arg;

	if (td->timeout.tv_sec != 0 || td->timeout.tv_nsec != 0) {
		rumpuser_mutex_enter(task->mtx);
		err = rumpuser_cv_timedwait(task->cv, task->mtx,
					    td->timeout.tv_sec, td->timeout.tv_nsec);
		if (task->canceled) {
			if (!task->thrid) {
				rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)task);
				nuse_release_task(task);
				free(td);
			}
			goto end;
		}
		rumpuser_mutex_exit(task->mtx);
		if (err && err != rumpuser__errtrans(ETIMEDOUT))
			goto end;
	}

#ifdef notyet
	nuse_schedule();
#endif
	lib_assert(f);
	f(thrarg);

	rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)task);
	nuse_release_task(task);
	free(td);
end:
	lib_update_jiffies();
	return arg;
}

struct SimTask *nuse_task_start(struct SimKernel *kernel, 
				void (*func) (void *), void *arg)
{
	int pri = 0;
	int rv;
	struct thrdesc *td;
	int joinable = 1;
	char *name = "task";

	td = malloc(sizeof(*td));
	memset(td, 0, sizeof(*td));
	td->newlwp = nuse_new_task(name);
	rumpuser_curlwpop(RUMPUSER_LWP_CREATE, (struct lwp *)td->newlwp);

	td->f = func;
	td->arg = arg;

	rv = rumpuser_thread_create(nuse_task_start_trampoline, td, name,
				    joinable, pri, -1, &td->newlwp->thrid);
	if (rv) {
		rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)td->newlwp);
		nuse_release_task(td->newlwp);
		free(td);
		return NULL;
	}

	return td->newlwp->s_task;
}

void *nuse_event_schedule_ns(struct SimKernel *kernel,
			     __u64 ns, void (*func) (void *arg), void *arg,
			     void (*dummy_fn)(void))
{
	int pri = 0;
	int rv;
	struct thrdesc *td;
	int joinable = 0;
	char *name = "timer";

	td = malloc(sizeof(*td));
	memset(td, 0, sizeof(*td));
	td->newlwp = nuse_new_task(name);
	rumpuser_curlwpop(RUMPUSER_LWP_CREATE, (struct lwp *)td->newlwp);

	td->f = func;
	td->arg = arg;

#define NSEC_PER_SEC	1000000000L
	td->timeout = ((struct timespec) { .tv_sec = ns / NSEC_PER_SEC,
				.tv_nsec = ns % NSEC_PER_SEC });

	rv = rumpuser_thread_create(nuse_task_start_trampoline, td, name,
				    joinable, pri, -1, &td->newlwp->thrid);
	if (rv) {
		rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)td->newlwp);
		nuse_release_task(td->newlwp);
		free(td);
		return NULL;
	}

	return td;
}

void nuse_event_cancel(struct SimKernel *kernel, void *event)
{
	struct thrdesc *td = event;
	struct NuseTask *task = td->newlwp;

	if (task->canceled) {
		return;
	}

	task->canceled = 1;
	rumpuser_mutex_enter(task->mtx);
	rumpuser_cv_signal(task->cv);
	rumpuser_mutex_exit(task->mtx);

	if (task->thrid) {
		rumpuser_thread_join(task->thrid);

		rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)task);
		nuse_release_task(task);
		free(td);
	}
}

void nuse_task_wait(struct SimKernel *kernel)
{
	struct SimTask *lib_task = nuse_task_current(NULL);
	struct NuseTask *task = g_exported->task_get_private(lib_task);

	lib_assert(task != NULL);

	rumpuser_mutex_enter(task->mtx);
	rumpuser_cv_wait(task->cv, task->mtx);
	rumpuser_mutex_exit(task->mtx);
	lib_update_jiffies();
}

int nuse_task_wakeup(struct SimKernel *kernel, struct SimTask *lib_task)
{
	struct NuseTask *task = g_exported->task_get_private(lib_task);
	int nwaiters;

	lib_assert(task != NULL);
	rumpuser_cv_has_waiters(task->cv, &nwaiters);
//	if (nwaiters)
		rumpuser_cv_signal(task->cv);
	return nwaiters ? 1 : 0;
}

/* XXX */
static inline struct timespec timespec_add(struct timespec lhs,
						struct timespec rhs)
{
	struct timespec ts_delta;
	rumpns_set_normalized_timespec(&ts_delta, lhs.tv_sec + rhs.tv_sec,
				lhs.tv_nsec + rhs.tv_nsec);
	return ts_delta;
}

void lib_update_jiffies(void);
/* clock thread routine */
static void* nuse_clock_thread(void *noarg)
{
	struct timespec thetick, curclock;
	int64_t sec;
	long nsec;
	int error;

	error = rumpuser_clock_gettime(RUMPUSER_CLOCK_ABSMONO, &sec, &nsec);
	if (error)
		rumpns_panic("clock: cannot get monotonic time\n");

	curclock.tv_sec = sec;
	curclock.tv_nsec = nsec;
	thetick.tv_sec = 0;
	thetick.tv_nsec = 1000000000/HZ;


	for (;;) {
		lib_update_jiffies();

		error = rumpuser_clock_sleep(RUMPUSER_CLOCK_ABSMONO,
					     curclock.tv_sec, curclock.tv_nsec);
		if (error)
			rumpns_panic("clock sleep failure\n");
		timespec_add(curclock, thetick);
	}

	/* should not reach */
	return NULL;
}

void nuse_sched_init(void)
{
	int rv;
	rv = rumpuser_thread_create(nuse_clock_thread, NULL, "clock",
				    0, 0, -1, NULL);
	if (rv)
		rumpns_panic("thread create failure\n");
}

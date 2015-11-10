/*
 * Scheduler proxy of NUSE for rumpuser backend
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 */

#ifndef RUMP_SCHED_H
#define RUMP_SCHED_H

#include <sys/queue.h>
#include "sim-types.h"

struct rump_task {
	struct SimTask *s_task;
	void *thrid;
	int canceled;
	char name[16];
	struct rumpuser_cv *cv;
	struct rumpuser_mtx *mtx;
	void *rump_client;
	unsigned long pid;

	LIST_ENTRY(rump_task) entries;
};

/* rump-sched.h */
void rump_sched_init(void);
struct rump_task *rump_new_task(char *name);
void rump_release_task(struct rump_task *task);
struct rump_task *rump_find_task(unsigned long pid);
struct SimTask *rump_task_current(struct SimKernel *kernel);
struct SimTask *rump_task_start(struct SimKernel *kernel,
				void (*callback)(void *), void *context);
void *rump_event_schedule_ns(struct SimKernel *kernel,
			     __u64 ns, void (*fn) (void *context),
			     void *context, void (*dummy_fn)(void));
void rump_event_cancel(struct SimKernel *kernel, void *event);
void rump_task_wait(struct SimKernel *kernel);
int rump_task_wakeup(struct SimKernel *kernel, struct SimTask *task);
void rump_thread_allow(struct lwp *l);

#endif /* RUMP_SCHED_H */

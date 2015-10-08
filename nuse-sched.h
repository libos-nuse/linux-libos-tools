/*
 * Scheduler proxy of NUSE for rumpuser backend
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 */

#ifndef NUSE_SCHED_H
#define NUSE_SCHED_H

#include <sys/queue.h>
#include "sim-types.h"

struct nuse_task {
	struct SimTask *s_task;
	void *thrid;
	int canceled;
	char name[16];
	struct rumpuser_cv *cv;
	struct rumpuser_mtx *mtx;
	void *rump_client;
	unsigned long pid;

	LIST_ENTRY(nuse_task) entries;
};

/* nuse-sched.h */
void nuse_sched_init(void);
struct nuse_task *nuse_new_task(char *name);
void nuse_release_task(struct nuse_task *task);
struct nuse_task *nuse_find_task(unsigned long pid);
struct SimTask *nuse_task_current(struct SimKernel *kernel);
struct SimTask *nuse_task_start(struct SimKernel *kernel,
				void (*callback)(void *), void *context);
void *nuse_event_schedule_ns(struct SimKernel *kernel,
			     __u64 ns, void (*fn) (void *context),
			     void *context, void (*dummy_fn)(void));
void nuse_event_cancel(struct SimKernel *kernel, void *event);
void nuse_task_wait(struct SimKernel *kernel);
int nuse_task_wakeup(struct SimKernel *kernel, struct SimTask *task);

#endif /* NUSE_SCHED_H */

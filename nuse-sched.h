/*
 * Scheduler proxy of NUSE for rumpuser backend
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 */

#include "sim-types.h"

struct NuseTask {
	struct SimTask *s_task;
	void *thrid;
	int canceled;
	char name[16];
	struct rumpuser_cv *cv;
	struct rumpuser_mtx *mtx;
};

extern struct NuseTask *lwp0;

/* nuse-sched.h */
void nuse_sched_init(void);
struct NuseTask *nuse_new_task(char *name);
void nuse_release_task(struct NuseTask *task);
struct SimTask *nuse_task_current(struct SimKernel *kernel);
struct SimTask *nuse_task_start(struct SimKernel *kernel, 
				void (*callback) (void *), void *context);
void *nuse_event_schedule_ns(struct SimKernel *kernel,
			     __u64 ns, void (*fn) (void *context), void *context,
			     void (*dummy_fn)(void));
void nuse_event_cancel(struct SimKernel *kernel, void *event);
void nuse_task_wait(struct SimKernel *kernel);
int nuse_task_wakeup(struct SimKernel *kernel, struct SimTask *task);

/* nuse-syscall.c */
void nuse_schedule(void);


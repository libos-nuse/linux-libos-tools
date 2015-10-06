/*
 * Rump hypercall interface for Linux
 */

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>

#include <rump/rumpuser_port.h>
#include <rump/rump.h> /* XXX: for rfork flags */
#include <rump/rumpuser.h>
#include <generated/rump_syscalls.h>

#include <generated/utsrelease.h>
#include <generated/compile.h>

#include <asm/types.h>
#include "nuse-sched.h"

#define RUMPSERVER_DEFAULT "/tmp/rump-server-nuse"

int
rump_daemonize_begin(void)
{
	return 0;
}

int
rump_daemonize_done(int error)
{
	return 0;
}

int
rump_pub_etfs_register_withsize(const char *arg1, const char *arg2, enum rump_etfs_type arg3, uint64_t arg4, uint64_t arg5)
{
	return 0;
}

int
rump_pub_etfs_register(const char *arg1, const char *arg2, enum rump_etfs_type arg3)
{
	return 0;
}

int
rump_pub_etfs_remove(const char *arg1)
{
	return 0;
}

int
rump_syscall(int num, void *data, size_t dlen, register_t *retval)
{
	int rv = 0;
	sys_call_ptr_t syscall = NULL;
	struct syscall_args *args;
	args = (struct syscall_args *)data;

	syscall = rump_sys_call_table[num];
	if (!syscall) {
		retval[0] = -1;
		return -1;
	}

	rv = ((long (*)(long, long, long, long, long, long))syscall)(args->args[0],
								args->args[1],
								args->args[2],
								args->args[3],
								args->args[4],
								args->args[5]);
	/* FIXME: need better err translation */
	if (rv < 0) {
		retval[0] = -rv;
		rv = -1;
	}
	return rv;
}

/* FIXME */
struct task_struct;
typedef struct { unsigned long seg; } mm_segment_t;
struct thread_info {
	unsigned int flags;
	int preempt_count;
	struct task_struct *task;
	mm_segment_t addr_limit;
	void* restart_block;
};
struct thread_info *rumpns_current_thread_info(void);

static int
rump_libos_hyp_syscall(int num, void *arg, long *retval)
{
	int ret;
	/* XXX */
	mm_segment_t oldfs = rumpns_current_thread_info()->addr_limit;
	rumpns_current_thread_info()->addr_limit = (mm_segment_t) { (-2) };

	ret = rump_syscall(num, arg, 0, retval);

	rumpns_current_thread_info()->addr_limit = oldfs;
	return ret;
}

static int
rump_libos_lwproc_rfork(void *priv, int flags, const char *comm)
{
	struct nuse_task *task = nuse_new_task((char *)comm);
	task->rump_client = priv; /* store struct spc_client */

	rumpuser_curlwpop(RUMPUSER_LWP_CREATE, (struct lwp *)task);
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)task);

	return 0;
}

static void
rump_libos_lwproc_release(void)
{
	struct nuse_task *task = (struct nuse_task *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, (struct lwp *)task);
	return;
}

static void
rump_libos_lwproc_switch(struct lwp *newlwp)
{
	struct nuse_task *task = (struct nuse_task *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, (struct lwp *)task);
	rumpuser_curlwpop(RUMPUSER_LWP_SET, newlwp);
}

/* find nuse_task created by rfork */
static int
rump_libos_lwproc_newlwp(pid_t pid)
{
	/* find nuse_task */
	struct nuse_task *task = nuse_find_task(pid);
	if (!task) {
		rumpuser_dprintf("could not found pid %d\n", pid);
		return ESRCH;
	}

	/* set to currnet */
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)task);

	return 0;
}

static struct lwp *
rump_libos_lwproc_curlwp(void)
{
	return rumpuser_curlwp();
}

static void
rump_libos_hyp_lwpexit(void)
{
	struct nuse_task *task = (struct nuse_task *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)task);
	nuse_release_task(task);
}

static pid_t
rump_libos_hyp_getpid(void)
{
	struct nuse_task *task = (struct nuse_task *)rumpuser_curlwp();
	return task->pid;
}

void *
rump_is_remote_client(void)
{
	struct nuse_task *task = (struct nuse_task *)rumpuser_curlwp();

	return task->rump_client;
}

static void rump_libos_schedule(void){}
static void rump_libos_unschedule(void){}
static void rump_libos_user_unschedule(int nlocks, int *countp, void *interlock){}
static void rump_libos_user_schedule(int nlocks, void *interlock){}
static void rump_libos_hyp_execnotify(const char *comm){}

static const struct rumpuser_hyperup hyp = {
	.hyp_schedule		= rump_libos_schedule,
	.hyp_unschedule		= rump_libos_unschedule,
	.hyp_backend_unschedule	= rump_libos_user_unschedule,
	.hyp_backend_schedule	= rump_libos_user_schedule,
	.hyp_lwproc_switch	= rump_libos_lwproc_switch,
	.hyp_lwproc_release	= rump_libos_lwproc_release,
	.hyp_lwproc_rfork	= rump_libos_lwproc_rfork,
	.hyp_lwproc_newlwp	= rump_libos_lwproc_newlwp,
	.hyp_lwproc_curlwp	= rump_libos_lwproc_curlwp,
	.hyp_lwpexit		= rump_libos_hyp_lwpexit,
	.hyp_syscall		= rump_libos_hyp_syscall,
	.hyp_execnotify		= rump_libos_hyp_execnotify,
	.hyp_getpid		= rump_libos_hyp_getpid,
};

void
rump_syscall_proxy_init(void)
{
	char *url;
	char buf[64];

	url = getenv("RUMP_SERVER");
	if (!url) {
		sprintf(buf, "unix://%s.%d", RUMPSERVER_DEFAULT, getpid());
		url = strdup(buf);
	}
	umask (0007);
	rumpuser_sp_init(url, "Linux", UTS_RELEASE, UTS_MACHINE);
	rumpuser_dprintf("===rump syscall proxy start at %s===\n", url);
}


/* user by separated sysproxy? */
int
rump_init_server(const char *url)
{
	setenv("RUMP_SERVER", url, 1);
	rump_syscall_proxy_init();
	return 0;
}

int
rump_init(void)
{
	if (rumpuser_init(RUMPUSER_VERSION, &hyp) != 0) {
		rumpuser_dprintf("rumpuser init failed\n");
		return EINVAL;
	}

	rump_syscall_proxy_init();
//	nuse_init();
	return 0;
}

void
rump_exit(void)
{
	rumpuser_dprintf("rump_server finishing.\n");
	rumpuser_sp_fini(NULL);
}

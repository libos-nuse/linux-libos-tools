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
#include <time.h>

#include <rump/rumpuser_port.h>
#include <rump/rump.h> /* XXX: for rfork flags */
#include <rump/rumpuser.h>
#include <generated/rump_syscalls.h>

#include <generated/utsrelease.h>
#include <generated/compile.h>

#include <asm/types.h>
#include "sim-init.h"
#include "sim-assert.h"
#include "sim.h"
#include "rump-sched.h"
#include "nuse-hostcalls.h"
#include "nuse.h"

#define RUMPSERVER_DEFAULT "/tmp/rump-server-nuse"
struct SimExported *g_exported = NULL;

extern void lib_init(struct SimExported *exported,
		const struct SimImported *imported,
		struct SimKernel *kernel);

static void rump_libos_hyp_lwpexit(void);
static struct lwp *rump_libos_lwproc_curlwp(void);
static int rump_libos_lwproc_newlwp(pid_t pid);
static void rump_libos_lwproc_switch(struct lwp *newlwp);
static void rump_libos_lwproc_release(void);
static int rump_libos_lwproc_rfork(void *priv, int flags, const char *comm);
#define rump_schedule(x)
#define rump_unschedule(x)

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
rump_pub_etfs_register_withsize(const char *arg1, const char *arg2,
				enum rump_etfs_type arg3,
				uint64_t arg4, uint64_t arg5)
{
	return 0;
}

int
rump_pub_etfs_register(const char *arg1, const char *arg2,
		       enum rump_etfs_type arg3)
{
	return 0;
}

int
rump_pub_etfs_remove(const char *arg1)
{
	return 0;
}


int
rump_pub_lwproc_rfork(int arg1)
{
	int rv = 0;

	rump_schedule();
//	rv = rump_libos_lwproc_rfork(arg1);
	rump_unschedule();

	return rv;
}

int
rump_pub_lwproc_newlwp(pid_t arg1)
{
	int rv;

	rump_schedule();
	rv = rump_libos_lwproc_newlwp(arg1);
	rump_unschedule();

	return rv;
}

void
rump_pub_lwproc_switch(struct lwp *arg1)
{

	rump_schedule();
	rump_libos_lwproc_switch(arg1);
	rump_unschedule();
}

void
rump_pub_lwproc_releaselwp(void)
{

	rump_schedule();
	rump_libos_lwproc_release();
	rump_unschedule();
}

struct lwp *
rump_pub_lwproc_curlwp(void)
{
	struct lwp * rv;

	rump_schedule();
	rv = rump_libos_lwproc_curlwp();
	rump_unschedule();

	return rv;
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

	rv = ((long (*)(long, long, long, long, long, long))
	      syscall) (args->args[0],
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
typedef struct { unsigned long seg; } mm_segment_t;
struct thread_info {
	unsigned int flags;
	int preempt_count;
	struct task_struct *task;
	mm_segment_t addr_limit;
	void *restart_block;
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
	struct rump_task *task = rump_new_task((char *)comm);

	task->rump_client = priv; /* store struct spc_client */

	rumpuser_curlwpop(RUMPUSER_LWP_CREATE, (struct lwp *)task);
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)task);

	return 0;
}

static void
rump_libos_lwproc_release(void)
{
	struct rump_task *task = (struct rump_task *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, (struct lwp *)task);
}

static void
rump_libos_lwproc_switch(struct lwp *newlwp)
{
	struct rump_task *task = (struct rump_task *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, (struct lwp *)task);
	rumpuser_curlwpop(RUMPUSER_LWP_SET, newlwp);
}

/* find rump_task created by rfork */
static int
rump_libos_lwproc_newlwp(pid_t pid)
{
	/* find rump_task */
	struct rump_task *task = rump_find_task(pid);

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
	struct rump_task *task = (struct rump_task *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)task);
	rump_release_task(task);
}

static pid_t
rump_libos_hyp_getpid(void)
{
	struct rump_task *task = (struct rump_task *)rumpuser_curlwp();

	return task->pid;
}

void *
rump_is_remote_client(void)
{
	struct rump_task *task = (struct rump_task *)rumpuser_curlwp();

	return task->rump_client;
}

static void rump_libos_schedule(void) {}
static void rump_libos_unschedule(void) {}
static void rump_libos_user_unschedule(int nlocks, int *countp,
				       void *interlock) {}
static void rump_libos_user_schedule(int nlocks, void *interlock) {}
static void rump_libos_hyp_execnotify(const char *comm) {}

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
	umask(0007);
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

int rump_vprintf(struct SimKernel *kernel, const char *str, va_list args)
{
	rumpuser_dprintf(str, args);
	return 0;
}
void *rump_malloc(struct SimKernel *kernel, unsigned long size)
{
	void *mem;

	rumpuser_malloc(size, 8, &mem);
	return mem;
}
void rump_free(struct SimKernel *kernel, void *buffer)
{
	return rumpuser_free(buffer, -1); /* XXX */
}

void *rump_memcpy(struct SimKernel *kernel, void *dst, const void *src,
		unsigned long size)
{
	char *tmp = dst;
	const char *s = src;

	while (size--)
		*tmp++ = *s++;
	return dst;
}
void *rump_memset(struct SimKernel *kernel, void *dst, char value,
		unsigned long size)
{
	unsigned char *ptr = dst;

	while (size--)
		*ptr++ = (unsigned char)value;

	return dst;
}
__u64 rump_current_ns(struct SimKernel *kernel)
{
	struct timespec tp;
	static __u64 init_ns = -1;


	if (rumpuser_clock_gettime(RUMPUSER_CLOCK_ABSMONO, &tp.tv_sec,
				   &tp.tv_nsec) == -1)
		return init_ns;

	if (init_ns == -1)
		init_ns = tp.tv_sec * 1000000000 + tp.tv_nsec;

	return tp.tv_sec * 1000000000 + tp.tv_nsec - init_ns;
}
unsigned long rump_random(struct SimKernel *kernel)
{
	unsigned long val, randlen;

	rumpuser_getrandom(&val, sizeof(val), 0, &randlen);
	return val;
}
char *nuse_getenv(struct SimKernel *kernel, const char *name)
{
	return host_getenv(name);
}
int nuse_fclose(struct SimKernel *kernel, FILE *fp)
{
	return host_fclose(fp);
}
size_t nuse_fwrite(struct SimKernel *kernel, const void *ptr,
		size_t size, size_t nmemb, FILE *stream)
{
	return host_fwrite(ptr, size, nmemb, stream);
}
int nuse_access(struct SimKernel *kernel, const char *pathname, int mode)
{
	return host_access(pathname, mode);
}
int nuse_atexit(void (*function)(void))
{
	/* XXX: need to handle host_atexit, but can't dynamically resolv 
	   the symbol so, ignore it for the time being */
	return 0;
}

void rump_signal_raised(struct SimKernel *kernel, struct SimTask *task, int sig)
{
	static int logged = 0;

	if (!logged) {
		lib_printf("%s: Not implemented yet\n", __func__);
		logged = 1;
	}
}

void
libos_init(void)
{
	/* are those rump hypercalls? */
	struct SimImported *imported;
	rumpuser_malloc(sizeof(struct SimImported), 8, (void **)&imported);
	rump_memset(NULL, imported, 0, sizeof(struct SimImported));
	imported->vprintf = rump_vprintf;
	imported->malloc = rump_malloc;
	imported->free = rump_free;
	imported->memcpy = rump_memcpy;
	imported->memset = rump_memset;
	imported->atexit = NULL; /* not implemented */
	imported->access = nuse_access;
	imported->getenv = nuse_getenv;
	imported->mkdir = NULL; /* not implemented */
	/* it's not hypercall, but just a POSIX glue ? */
	imported->open = NULL;	   /* not used */
	imported->__fxstat = NULL; /* not implemented */
	imported->fseek = NULL; /* not implemented */
	imported->setbuf = NULL; /* not implemented */
	imported->ftell = NULL; /* not implemented */
	imported->fdopen = NULL; /* not implemented */
	imported->fread = NULL; /* not implemented */
	imported->fwrite = nuse_fwrite;
	imported->fclose = nuse_fclose;
	imported->random = rump_random;
	imported->event_schedule_ns = rump_event_schedule_ns;
	imported->event_cancel = rump_event_cancel;
	imported->current_ns = rump_current_ns;
	imported->task_start = rump_task_start;
	imported->task_wait = rump_task_wait;
	imported->task_current = rump_task_current;
	imported->task_wakeup = rump_task_wakeup;
	imported->task_yield = NULL; /* not implemented */
	imported->dev_xmit = nuse_dev_xmit;
	imported->signal_raised = rump_signal_raised;
	imported->poll_event = NULL;

	rumpuser_malloc(sizeof(struct SimExported), 8, (void **)&g_exported);

	lib_init (g_exported, imported, NULL);

}

int
rump_init(void)
{
	if (rumpuser_init(RUMPUSER_VERSION, &hyp) != 0) {
		rumpuser_dprintf("rumpuser init failed\n");
		return EINVAL;
	}

	libos_init();
	rump_sched_init();
	rump_consdev_init();

	return 0;
}

void
rump_exit(void)
{
	rumpuser_dprintf("rump_server finishing.\n");
	rumpuser_sp_fini(NULL);
}

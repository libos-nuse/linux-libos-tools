/*
 * Network stack in userspace (NUSE) for POSIX userspace backend
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 *         Ryo Nakamura <upa@wide.ad.jp>
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <linux/route.h>
#include <sys/ioctl.h>
#include "list.h"         /* linked-list */

#include "sim-init.h"
#include "sim-assert.h"
#include "sim.h"
#include "nuse.h"
#include "nuse-hostcalls.h"
#include "nuse-vif.h"
#include "nuse-config.h"
#include "nuse-libc.h"

struct SimTask;
struct SimExported *g_exported = NULL;

struct NuseTask {
	struct list_head head;
	struct SimTask *s_task;
};

int nuse_socket(int domain, int type, int protocol);
int nuse_ioctl(int fd, int request, ...);
int nuse_close(int fd);

int nuse_vprintf(struct SimKernel *kernel, const char *str, va_list args)
{
	return vprintf(str, args);
}
void *nuse_malloc(struct SimKernel *kernel, unsigned long size)
{
	return malloc(size);
}
void nuse_free(struct SimKernel *kernel, void *buffer)
{
	return free(buffer);
}

void *nuse_memcpy(struct SimKernel *kernel, void *dst, const void *src,
		unsigned long size)
{
	return memcpy(dst, src, size);
}
void *nuse_memset(struct SimKernel *kernel, void *dst, char value,
		unsigned long size)
{
	return memset(dst, value, size);
}
__u64 nuse_current_ns(struct SimKernel *kernel)
{
	struct timespec tp;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	return tp.tv_sec * 1000000000 + tp.tv_nsec;
}
unsigned long nuse_random(struct SimKernel *kernel)
{
	return random();
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
int atexit(void (*function)(void))
{
	/* XXX: need to handle host_atexit, but can't dynamically resolv 
	   the symbol so, ignore it for the time being */
	return 0;
}

static struct NuseTask *g_nuse_main_ctx = NULL;
struct list_head g_task_lists = LIST_HEAD_INIT(g_task_lists);

struct SimTask *nuse_task_current(struct SimKernel *kernel)
{
	struct NuseTask *task;
	void *fiber;

	list_for_each_entry(task, &g_task_lists, head) {
		void *fiber = g_exported->task_get_private(task->s_task);
		if (fiber && nuse_fiber_isself(fiber)) {
			return task->s_task;
		}
	}

	if (!g_nuse_main_ctx) {
		fiber = nuse_fiber_new_from_caller(1 << 16, "init");
		g_nuse_main_ctx = malloc(sizeof(struct NuseTask));
		g_nuse_main_ctx->s_task = g_exported->task_create(fiber, getpid());
		list_add_tail(&g_nuse_main_ctx->head, &g_task_lists);
	}
	return g_nuse_main_ctx->s_task;
}

struct NuseTaskTrampolineContext {
	void (*callback)(void *);
	void *context;
	struct NuseTask *task;
};

void
nuse_task_add(void *fiber)
{
	struct NuseTask *task = malloc(sizeof(struct NuseTask));
	task->s_task = g_exported->task_create(fiber, getpid());

	list_add_tail(&task->head, &g_task_lists);
}

static void *nuse_task_start_trampoline(void *context)
{
	/* we use this trampoline solely for the purpose of executing
	   lib_update_jiffies. prior to calling the callback. */
	struct NuseTaskTrampolineContext *ctx = context;
	int found = 0;
	struct NuseTask *task;

	void (*callback)(void *);
	void *callback_context;

	list_for_each_entry(task, &g_task_lists, head) {
		if (g_exported->task_get_private(task->s_task) ==
		    g_exported->task_get_private(ctx->task->s_task)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		printf("task not found\n");
		return NULL;
	}

	if (nuse_fiber_is_stopped(g_exported->task_get_private(ctx->task->s_task))) {
		lib_free(ctx);
		lib_update_jiffies();
		lib_printf("canceled\n");
		return NULL;
	}

	callback = ctx->callback;
	callback_context = ctx->context;
	task = ctx->task;
	lib_free(ctx);
	lib_update_jiffies();

	callback(callback_context);

	/*  nuse_fiber_free (task->private); */
	list_del(&task->head);
	free(task);

	return ctx;
}

struct SimTask *nuse_task_start(struct SimKernel *kernel, 
				void (*callback) (void *), void *context)
{
	struct NuseTask *task = NULL;
	struct NuseTaskTrampolineContext *ctx =
		lib_malloc(sizeof(struct NuseTaskTrampolineContext));

	if (!ctx)
		return NULL;
	ctx->callback = callback;
	ctx->context = context;

	void *fiber = nuse_fiber_new(&nuse_task_start_trampoline, ctx, 1 << 16,
				     "task");
	task = malloc(sizeof(struct NuseTask));
	task->s_task = g_exported->task_create(fiber, getpid());
	ctx->task = task;

	if (!nuse_fiber_is_stopped(g_exported->task_get_private(task->s_task)))
		list_add_tail(&task->head, &g_task_lists);

	nuse_fiber_start(fiber);
	return task->s_task;
}

void *nuse_event_schedule_ns(struct SimKernel *kernel,
			__u64 ns, void (*fn) (void *context), void *context,
			void (*dummy_fn)(void))
{
	struct NuseTask *task = NULL;
	struct NuseTaskTrampolineContext *ctx =
		lib_malloc(sizeof(struct NuseTaskTrampolineContext));
	void *fiber;

	if (!ctx)
		return NULL;
	ctx->callback = fn;
	ctx->context = context;

	/* without fiber_start (pthread) */
	fiber = nuse_fiber_new_from_caller(1 << 16, "task_sched");
	task = malloc(sizeof(struct NuseTask));
	task->s_task = g_exported->task_create(fiber, getpid());
	ctx->task = task;

	list_add_tail(&task->head, &g_task_lists);

	nuse_add_timer(ns, nuse_task_start_trampoline, ctx, fiber);

	return task;
}

void nuse_event_cancel(struct SimKernel *kernel, void *event)
{
	struct NuseTask *task = event;

	nuse_fiber_stop(g_exported->task_get_private(task->s_task));
	/*  nuse_fiber_free (task->private); */
	list_del(&task->head);
}

void nuse_task_wait(struct SimKernel *kernel)
{
	struct SimTask *task;

	task = nuse_task_current(NULL);
	lib_assert(task != NULL);
	nuse_fiber_wait(g_exported->task_get_private(task));
	lib_update_jiffies();
}

int nuse_task_wakeup(struct SimKernel *kernel, struct SimTask *task)
{
	return nuse_fiber_wakeup(g_exported->task_get_private(task));
}

void *
nuse_netdev_rx_trampoline(void *context)
{
	struct SimDevice *dev = context;
	struct nuse_vif *vif = g_exported->dev_get_private(dev);

	nuse_vif_read(vif, dev);
	printf("should not reach here %s\n", __func__);
	/* should not reach */
	return dev;
}

void
nuse_dev_rx(struct SimDevice *dev, char *buf, int size)
{
	struct ethhdr {
		unsigned char h_dest[6];
		unsigned char h_source[6];
		uint16_t h_proto;
	} *hdr = (struct ethhdr *)buf;

	struct SimDevicePacket packet = g_exported->dev_create_packet(dev, size);
	/* XXX: FIXME should not copy */
	memcpy(packet.buffer, buf, size);
	g_exported->dev_rx(dev, packet);
	lib_softirq_wakeup();
}

void
nuse_dev_xmit(struct SimKernel *kernel, struct SimDevice *dev,
	      unsigned char *data, int len, unsigned int flags)
{
	struct nuse_vif *vif = g_exported->dev_get_private(dev);

	nuse_vif_write(vif, dev, data, len, flags);
	lib_softirq_wakeup();
}

void nuse_signal_raised(struct SimKernel *kernel, struct SimTask *task, int sig)
{
	static int logged = 0;

	if (!logged) {
		lib_printf("%s: Not implemented yet\n", __func__);
		logged = 1;
	}
}

void
nuse_poll_event(int flag, void *context)
{
	pthread_cond_t *condvar;
	int ret;

	condvar = (pthread_cond_t *)context;
	ret = pthread_cond_signal(condvar);
	if (ret != 0)
		perror("pthread_cond_signal");
}

void
nuse_netdev_lo_up(void)
{
	int err;
	static int init_loopback = 0;
	struct ifreq ifr;

	/* loopback IFF_UP */
	if (!init_loopback) {
		memset(&ifr, 0, sizeof(struct ifreq));
		ifr.ifr_flags = IFF_UP;
		sprintf(ifr.ifr_name, "lo");
		int sock = nuse_socket(PF_INET, SOCK_DGRAM, 0);
		err = nuse_ioctl(sock, SIOCSIFFLAGS, &ifr);
		if (err)
			printf("err devinet_ioctl %d\n", err);
		init_loopback = 1;
		nuse_close(sock);
	}
}

void
nuse_netdev_create(struct nuse_vif_config *vifcf)
{
	/* create net_device for nuse process from nuse_vif_config */
	int err;
	struct nuse_vif *vif;
	struct ifreq ifr;
	struct NuseTask *task = NULL;
	void *fiber;
	int sock;
	struct SimDevice *dev;

	printf("create vif %s\n", vifcf->ifname);
	printf("  address = %s\n", vifcf->address);
	printf("  netmask = %s\n", vifcf->netmask);
	printf("  macaddr = %s\n", vifcf->macaddr);
	printf("  type    = %d\n", vifcf->type);

	if (vifcf->type == NUSE_VIF_PIPE) {
		printf("  path    = %s\n", vifcf->pipepath);
		vif = nuse_vif_create(vifcf->type, vifcf->pipepath);
	} else {
		vif = nuse_vif_create(vifcf->type, vifcf->ifname);
	}

	if (!vif) {
		printf("vif create error\n");
		lib_assert(0);
	}

	/* create new new_device */
	dev = g_exported->dev_create(vifcf->ifname, vif, 0);

	/* assign new hw address */
	if (vifcf->mac[0] == 0 && vifcf->mac[1] == 0 && vifcf->mac[2] == 0 &&
	    vifcf->mac[3] == 0 && vifcf->mac[4] == 0 && vifcf->mac[5] == 0) {
		/* eth_random_addr like */
		long int mac = random();
		memcpy(&vifcf->mac[2], &mac, sizeof(long int));
		vifcf->mac[0] &= 0xfe;	/* clear multicast bit */
		vifcf->mac[0] |= 0x02;	/* set local assignment bit (IEEE802) */

		printf("mac address for %s is randomized ", vifcf->ifname);
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
		       vifcf->mac[0], vifcf->mac[1], vifcf->mac[2],
		       vifcf->mac[3], vifcf->mac[4], vifcf->mac[5]);
	}
	g_exported->dev_set_address(dev, vifcf->mac);

	/* assign IPv4 address */
	/* XXX: ifr_name is already filed by nuse_config_parse_interface,
	   I don't know why, but vifcf->ifr_vif_addr.ifr_name is NULL here. */
	strcpy(vifcf->ifr_vif_addr.ifr_name, vifcf->ifname);

	sock = nuse_socket(PF_INET, SOCK_DGRAM, 0);
	err = nuse_ioctl(sock, SIOCSIFADDR, &vifcf->ifr_vif_addr);
	if (err) {
		perror("ioctl");
		printf("err ioctl for assign address %s for %s %d\n",
		       vifcf->address, vifcf->ifname, err);
	}

	/* set netmask */
	err = nuse_ioctl(sock, SIOCSIFNETMASK, &vifcf->ifr_vif_mask);
	if (err) {
		perror("ioctl");
		printf("err ioctl for assign netmask %s for %s %d\n",
		       vifcf->netmask, vifcf->ifname, err);
	}

	/* IFF_UP */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_UP;
	strncpy(ifr.ifr_name, vifcf->ifname, IFNAMSIZ);

	err = nuse_ioctl(sock, SIOCSIFFLAGS, &ifr);
	if (err) {
		perror("devinet_ioctl");
		printf("err devinet_ioctl to set ifup dev %s %d\n",
		       vifcf->ifname, err);
	}

	/* wait for packets */
	fiber = nuse_fiber_new(&nuse_netdev_rx_trampoline, dev,
			       1 << 16, "NET_RX");
	task = malloc(sizeof(struct NuseTask));
	task->s_task = g_exported->task_create(fiber, getpid());
	list_add_tail(&task->head, &g_task_lists);
	nuse_fiber_start(fiber);
}

void
nuse_route_install(struct nuse_route_config *rtcf)
{
	int err, sock;

	sock = nuse_socket(PF_INET, SOCK_DGRAM, 0);
	err = nuse_ioctl(sock, SIOCADDRT, &rtcf->route);
	if (err)
		printf("err ip_rt_ioctl to add route to %s via %s %d\n",
		       rtcf->network, rtcf->gateway, err);
	nuse_close(sock);

}

extern void lib_init(struct SimExported *exported,
		const struct SimImported *imported,
		struct SimKernel *kernel);

void __attribute__((constructor))
nuse_init(void)
{
	int n;
	char *config;
	struct nuse_config cf;

	nuse_hostcall_init();
	nuse_set_affinity();

	/* create descriptor table */
	memset(nuse_fd_table, 0, sizeof(nuse_fd_table));
	nuse_fd_table[1].real_fd = 1;
	nuse_fd_table[2].real_fd = 2;

	/* are those rump hypercalls? */
	struct SimImported *imported = malloc(sizeof(struct SimImported));
	memset(imported, 0, sizeof(struct SimImported));
	imported->vprintf = nuse_vprintf;
	imported->malloc = nuse_malloc;
	imported->free = nuse_free;
	imported->memcpy = nuse_memcpy;
	imported->memset = nuse_memset;
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
	imported->random = nuse_random;
	imported->event_schedule_ns = nuse_event_schedule_ns;
	imported->event_cancel = nuse_event_cancel;
	imported->current_ns = nuse_current_ns;
	imported->task_start = nuse_task_start;
	imported->task_wait = nuse_task_wait;
	imported->task_current = nuse_task_current;
	imported->task_wakeup = nuse_task_wakeup;
	imported->task_yield = NULL; /* not implemented */
	imported->dev_xmit = nuse_dev_xmit;
	imported->signal_raised = nuse_signal_raised;
	imported->poll_event = nuse_poll_event;

	g_exported = malloc(sizeof(struct SimExported));
	lib_init (g_exported, imported, NULL);

	/* loopback IFF_UP * / */
	nuse_netdev_lo_up();

	/* read and parse a config file */
	config = host_getenv("NUSECONF");
	if (config == NULL)
		printf("config file is not specified\n");
	else {
		if (!nuse_config_parse(&cf, config)) {
			printf("parse config file failed\n");
			lib_assert(0);
		}

		/* create netdevs specified by config file */
		for (n = 0; n < cf.vif_cnt; n++)
			nuse_netdev_create(cf.vifs[n]);

		/* setup route entries */
		for (n = 0; n < cf.route_cnt; n++)
			nuse_route_install(cf.routes[n]);
	}

	/* now it's ready to accept IPC */
	nuse_syscall_proxy_init();
}

void __attribute__((destructor))
nuse_exit(void)
{
	printf("finishing NUSE\n");
	nuse_syscall_proxy_exit();
}

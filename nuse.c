/*
 * Network stack in userspace (NUSE) for POSIX userspace backend
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 *         Ryo Nakamura <upa@wide.ad.jp>
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <linux/route.h>
#include <sys/ioctl.h>

#define HAVE_ALIGNED_ALLOC
#include <rump/rumpuser_port.h>
#include <rump/rumpuser.h>

#include "sim-init.h"
#include "sim-assert.h"
#include "sim.h"
#include "nuse.h"
#include "nuse-hostcalls.h"
#include "nuse-vif.h"
#include "nuse-config.h"
#include "nuse-sched.h"

struct SimTask;
struct SimExported *g_exported = NULL;


int nuse_vprintf(struct SimKernel *kernel, const char *str, va_list args)
{
	/* rumpuser_dprintf(str, args); */
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
	static __u64 init_ns = -1;


	clock_gettime(CLOCK_MONOTONIC, &tp);
	if (init_ns == -1)
		init_ns = tp.tv_sec * 1000000000 + tp.tv_nsec;

	return tp.tv_sec * 1000000000 + tp.tv_nsec - init_ns;
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
int nuse_atexit(void (*function)(void))
{
	/* XXX: need to handle host_atexit, but can't dynamically resolv 
	   the symbol so, ignore it for the time being */
	return 0;
}

struct thrdesc {
	struct SimDevice *dev;
	struct nuse_task *task;
};

void *
nuse_netdev_rx_trampoline(void *context)
{
	struct thrdesc *td = context;
	struct SimDevice *dev = td->dev;
	struct nuse_vif *vif = g_exported->dev_get_private(dev);

	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)td->task);
	nuse_vif_read(vif, dev);
	free(td);
	printf("should not reach here %s\n", __func__);
	/* should not reach */
	return dev;
}

void
nuse_dev_rx(struct SimDevice *dev, char *buf, int size)
{
#ifdef DEBUG
	struct ethhdr {
		unsigned char h_dest[6];
		unsigned char h_source[6];
		uint16_t h_proto;
	} *hdr = (struct ethhdr *)buf;
#endif

	struct SimDevicePacket packet = g_exported->dev_create_packet(dev, size);
	/* XXX: FIXME should not copy */
	memcpy(packet.buffer, buf, size);
	g_exported->dev_rx(dev, packet);
	lib_softirq_wakeup();
}

void
nuse_dev_xmit(struct SimKernel *kernel, struct SimDevice *dev,
	unsigned char *data, int len)
{
	struct nuse_vif *vif = g_exported->dev_get_private(dev);

	nuse_vif_write(vif, dev, data, len);
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
	struct nuse_task *task = NULL;
	int sock;
	struct SimDevice *dev;
	int joinable = 1;
	int pri = 0;
	struct thrdesc *td;
	char *name = "NET_RX";

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

		printf("  mac address for %s is randomized ", vifcf->ifname);
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
	task = nuse_new_task(name);
	rumpuser_curlwpop(RUMPUSER_LWP_CREATE, (struct lwp *)task);
	td = malloc(sizeof(*td));
	td->task = task;
	td->dev = dev;

	err = rumpuser_thread_create(nuse_netdev_rx_trampoline, td, name,
				     joinable, pri, -1, &task->thrid);
	if (err) {
		nuse_release_task(task);
		free(td);
		return;
	}

	return;
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
#if 1
	cpu_set_t cpuset;

	/* bind to cpu0 */
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset);
#endif

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

	/* now it's ready to accept rump IPC */
	rump_init();

	lib_init (g_exported, imported, NULL);
	nuse_sched_init();

	/* loopback IFF_UP */
	nuse_netdev_lo_up();
	/* for mac address randomization */
	srand(time(NULL));

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

}

void __attribute__((destructor))
nuse_exit(void)
{
	printf("finishing NUSE\n");
	rump_exit();
}

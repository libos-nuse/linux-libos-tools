/*
 * raw socket based virtual network interface feature for NUSE
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#define _GNU_SOURCE /* Get RTLD_NEXT */
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <net/if.h>
#include "nuse-hostcalls.h"
#include "nuse-vif.h"
#include "nuse.h"

#ifndef PACKET_QDISC_BYPASS
#define PACKET_QDISC_BYPASS		20
#endif /* PACKET_QDISC_BYPASS */

void
nuse_vif_raw_read(struct nuse_vif *vif, struct SimDevice *dev)
{
	int sock = vif->sock;
	char buf[8192];
	ssize_t size;
	struct pollfd x[1];

	x[0].fd = sock;
	x[0].events = POLLIN;

	while (1) {
		x[0].revents = 0;
		host_poll(x, 1, -1);

		size = host_read(sock, buf, sizeof(buf));
		if (size < 0) {
			printf("read error errno=%d\n", errno);
			host_close(sock);
			return;
		} else if (size == 0) {
			printf("read error: closed. errno=%d\n", errno);
			host_close(sock);
			return;
		}

		nuse_dev_rx(dev, buf, size);
	}

	printf("%s: should not reach", __func__);
}

void
nuse_vif_raw_write(struct nuse_vif *vif, struct SimDevice *dev,
		   unsigned char *data, int len)
{
	int sock = vif->sock;
	int ret = host_write(sock, data, len);

	if (ret == -1)
		perror("write");
}

void *
nuse_vif_raw_create(const char *ifname)
{
	int err;
	int sock = host_socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	struct sockaddr_ll ll;
	struct nuse_vif *vif;
	int val = 1;

	if (sock < 0)
		perror("socket");

	memset(&ll, 0, sizeof(ll));

	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = if_nametoindex(ifname);
	ll.sll_protocol = htons(ETH_P_ALL);
	err = host_bind(sock, (struct sockaddr *)&ll, sizeof(ll));
	if (err)
		perror("bind");

	err = host_setsockopt(sock, SOL_PACKET, PACKET_QDISC_BYPASS,
			      &val, sizeof(val));
	if (err)
		perror("sockopt(PACKET_QDISC_BYPASS)");


	vif = malloc(sizeof(struct nuse_vif));
	vif->sock = sock;
	vif->type = NUSE_VIF_RAWSOCK; /* FIXME */
	return vif;
}

void
nuse_vif_raw_delete(struct nuse_vif *vif)
{
	int sock = vif->sock;
	free(vif);
	host_close(sock);
}

static struct nuse_vif_impl nuse_vif_rawsock = {
	.read	= nuse_vif_raw_read,
	.write	= nuse_vif_raw_write,
	.create = nuse_vif_raw_create,
	.delete = nuse_vif_raw_delete,
};

extern struct nuse_vif_impl *nuse_vif[NUSE_VIF_MAX];

int __attribute__((constructor))
nuse_vif_rawsock_init(void)
{
	nuse_vif[NUSE_VIF_RAWSOCK] = &nuse_vif_rawsock;
	return 0;
}
__define_initcall(nuse_vif_rawsock_init, 1);

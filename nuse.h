/*
 * Network stack in userspace (NUSE) for POSIX userspace backend
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 */

#ifndef NUSE_H
#define NUSE_H

struct pollfd;
struct SimDevice;
struct SimSocket;

/* nuse.c */
struct nuse_socket {
	struct SimSocket *kern_sock;
	int refcnt;
	int flags;
};

struct nuse_fd {
	int real_fd;
	struct epoll_fd *epoll_fd;
	struct nuse_socket *nuse_sock;
};
extern struct nuse_fd nuse_fd_table[1024];
void nuse_dev_rx(struct SimDevice *dev, char *buf, int size);

/* nuse-poll.c */
int nuse_poll(struct pollfd *fds, unsigned int nfds,
	struct timespec *end_time);

/* nuse-syscalls.c */
void nuse_syscall_proxy_init(void);
void nuse_syscall_proxy_exit(void);

#endif /* NUSE_H */

/*
 * system calls glue code for NUSE
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 *
 * Note: some of the code is picked from rumpkernel, written by Antti Kantee.
 */

#include <unistd.h>
#include <linux/types.h>
#include <stdio.h>
#include <sys/types.h>
#define __USE_GNU
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>

#include <rump/rumpuser_port.h>
#include <rump/rumpuser.h>
#include <generated/rump_syscalls.h>

#include "nuse-hostcalls.h"
#include "nuse.h"
#include "sim-init.h"
#include "sim.h"

#define weak_alias(name, aliasname)					\
	extern __typeof (name) aliasname __attribute__ ((weak, alias (# name)))

#define RUMP_FD_OFFSET (256/2)

int nuse_socket(int domain, int type, int protocol)
{
	if (domain == AF_UNIX) {
		if (!host_socket) nuse_hostcall_init();
		return host_socket (domain, type, protocol);
	}

	return rump___sysimpl_socket(domain, type, protocol);
}
weak_alias(nuse_socket, socket);

int nuse_close(int fd)
{
	if (fd < RUMP_FD_OFFSET) {
		if (!host_close) nuse_hostcall_init();
		return host_close(fd);
	}

	return rump___sysimpl_close(fd);
}
weak_alias(nuse_close, close);

ssize_t nuse_recvmsg(int fd, struct msghdr *msghdr, int flags)
{
	return rump___sysimpl_recvmsg(fd, msghdr, flags);
}
weak_alias(nuse_recvmsg, recvmsg);

/* XXX: timeout is not implemented. */
int nuse_recvmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen,
		  int flags, const struct timespec *timeout)
{
	int err, datagrams;
	struct mmsghdr *entry;

	datagrams = 0;
	entry = msgvec;
	err = 0;

	while (datagrams < vlen) {
		err = nuse_recvmsg(fd,
				   (struct msghdr *)entry,
				   flags);
		if (err < 0)
			break;
		entry->msg_len = err;
		++entry;
		++datagrams;
	}

	/* We only return an error if no datagrams were able to be recvmmsg */
	if (datagrams != 0)
		return datagrams;

	return err;
}
/*
 * FIXME: recvmmsg has different prototypes in different libc(s) ?
 * such as recvmmsg(...., const struct timespec *) or
 * recvmmsg(....,  struct timespec *) etc.
 * so disable weak alias for a while.
 * 
 */
#if 0
weak_alias(nuse_recvmmsg, recvmmsg);
weak_alias(nuse_recvmmsg, __recvmmsg);
#endif

ssize_t nuse_sendmsg(int fd, const struct msghdr *msghdr, int flags)
{
	if (fd < RUMP_FD_OFFSET)
		return host_sendmsg(fd, msghdr, flags);
	return rump___sysimpl_sendmsg(fd, (struct msghdr *)msghdr, flags);
}
weak_alias(nuse_sendmsg, sendmsg);

int nuse_sendmmsg(int fd, struct mmsghdr *msghdr, unsigned int vlen,
		  int flags)
{
	return rump___sysimpl_sendmmsg(fd, msghdr, vlen, flags);
}
weak_alias(nuse_sendmmsg, sendmmsg);
weak_alias(nuse_sendmmsg, __sendmmsg);

int nuse_getsockname(int fd, struct sockaddr *name, socklen_t *namelen)
{
	return rump___sysimpl_getsockname(fd, name, (int *)namelen);
}
weak_alias(nuse_getsockname, getsockname);

int nuse_getpeername(int fd, struct sockaddr *name, socklen_t *namelen)
{
	return rump___sysimpl_getpeername(fd, name, (int *)namelen);
}
weak_alias(nuse_getpeername, getpeername);

int nuse_bind(int fd, const struct sockaddr *name, socklen_t namelen)
{
	if (fd < RUMP_FD_OFFSET)
		return host_bind(fd, name, namelen);

	return rump___sysimpl_bind(fd, (struct sockaddr *)name, namelen);
}
weak_alias(nuse_bind, bind);

int nuse_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	return rump___sysimpl_connect(fd, (struct sockaddr *)addr, len);
}
weak_alias(nuse_connect, connect);

int nuse_listen(int fd, int backlog)
{
	if (fd < RUMP_FD_OFFSET)
		return host_listen(fd, backlog);
	return rump___sysimpl_listen(fd, backlog);
}
weak_alias(nuse_listen, listen);

#if 0
int nuse_shutdown(int fd, int how)
{
	if (fd < RUMP_FD_OFFSET)
		return host_shutdown(fd, how);
	return rump___sysimpl_shutdown(fd, how);
}
#endif

int nuse_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (fd < RUMP_FD_OFFSET)
		return host_accept(fd, addr, addrlen);
	return rump___sysimpl_accept(fd, addr, (int *)addrlen);
}
weak_alias(nuse_accept, accept);

ssize_t nuse_write(int fd, const void *buf, size_t count)
{
	if (fd < RUMP_FD_OFFSET) {
		if (!host_write) nuse_hostcall_init();
		return host_write(fd, buf, count);
	}
	return rump___sysimpl_write(fd, (void *)buf, count);
}
weak_alias(nuse_write, write);

ssize_t nuse_writev(int fd, const struct iovec *iov, int count)
{
	if (fd < RUMP_FD_OFFSET) {
		if (!host_writev) nuse_hostcall_init();
		return host_writev(fd, iov, count);
	}
	return rump___sysimpl_writev(fd, (void *)iov, count);
}
weak_alias(nuse_writev, writev);

ssize_t nuse_sendto(int fd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, unsigned int addrlen)
{
	if (fd < RUMP_FD_OFFSET)
		return host_sendto(fd, buf, len, flags, dest_addr, addrlen);
	return rump___sysimpl_sendto(fd, (void *)buf, len, flags,
				     (struct sockaddr *)dest_addr, addrlen);
}
weak_alias(nuse_sendto, sendto);

ssize_t nuse_send(int fd, const void *buf, size_t len, int flags)
{
	return nuse_sendto(fd, buf, len, flags, 0, 0);
}
weak_alias(nuse_send, send);

ssize_t nuse_read(int fd, void *buf, size_t count)
{
	if (fd < RUMP_FD_OFFSET) {
		if (!host_read) nuse_hostcall_init();
		return host_read(fd, buf, count);
	}
	return rump___sysimpl_read(fd, (void *)buf, count);
}
weak_alias(nuse_read, read);

ssize_t nuse_recvfrom(int fd, void *buf, size_t len, int flags,
		      struct sockaddr *from, socklen_t *fromlen)
{
	return rump___sysimpl_recvfrom(fd, buf, len, flags, from,
				       (int *)fromlen);
}
weak_alias(nuse_recvfrom, recvfrom);

ssize_t nuse_recv(int fd, void *buf, size_t count, int flags)
{
	return nuse_recvfrom(fd, buf, count, flags, 0, 0);
}
weak_alias(nuse_recv, recv);

int nuse_setsockopt(int fd, int level, int optname,
		    const void *optval, socklen_t optlen)
{
	if (fd < RUMP_FD_OFFSET)
		return host_setsockopt(fd, level, optname, optval, optlen);
	return rump___sysimpl_setsockopt(fd, level, optname,
					 (void *)optval, optlen);
}
weak_alias(nuse_setsockopt, setsockopt);

int nuse_getsockopt(int fd, int level, int optname,
		    void *optval, socklen_t *optlen)
{
	return rump___sysimpl_getsockopt(fd, level, optname,
					 optval, (int *)optlen);
}
weak_alias(nuse_getsockopt, getsockopt);

int nuse_ioctl(int fd, int request, ...)
{
	va_list vl;
	char *argp;

	va_start(vl, request);
	argp = va_arg(vl, char *);
	va_end(vl);

	if (fd < RUMP_FD_OFFSET) {
		if (!host_ioctl) nuse_hostcall_init();
		return host_ioctl(fd, request, argp);
	}
	return rump___sysimpl_ioctl(fd, request, (unsigned long)argp);
}
weak_alias(nuse_ioctl, ioctl);

int nuse_fcntl(int fd, int cmd, ... /* arg */)
{
	va_list vl;
	int *argp;

	va_start(vl, cmd);
	argp = va_arg(vl, int *);
	va_end(vl);

	if (fd < RUMP_FD_OFFSET) {
		if (!host_fcntl) nuse_hostcall_init();
		return host_fcntl(fd, cmd, argp);
	}
	return rump___sysimpl_fcntl(fd, cmd, (unsigned long)argp);
}
weak_alias(nuse_fcntl, fcntl);

int nuse_open(const char *pathname, int flags, ...)
{
	va_list vl;
	int real_fd;

	va_start(vl, flags);
	if (!host_open) nuse_hostcall_init();
	real_fd = host_open(pathname, flags, va_arg(vl, mode_t));
	va_end(vl);
	return real_fd;
}

int open64(const char *pathname, int flags, mode_t mode)
{
	if (!host_open64) nuse_hostcall_init();
	int real_fd = host_open64(pathname, flags, mode);
	return real_fd;
}

int nuse_pipe(int pipefd[2])
{
	return rump___sysimpl_pipe(pipefd);
}
weak_alias(nuse_pipe, pipe);

int
nuse_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	/* FIXME: should handle mixed case (rumpfd+hostfd) */
	if (fds[0].fd < RUMP_FD_OFFSET)
		return host_poll(fds, nfds, timeout);
	return rump___sysimpl_poll(fds, nfds, timeout);
}
weak_alias(nuse_poll, __poll);
weak_alias(nuse_poll, poll);

int
nuse_select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	/* FIXME: should handle mixed case (rumpfd+hostfd) */
	int fd, host_flag = 0;
	for (fd = 0; fd < nfds; fd++) {
		if (fd > RUMP_FD_OFFSET)
			break;

		if (readfds != 0 && FD_ISSET(fd, readfds)) {
			host_flag = 1;
			break;
		}
		if (writefds != 0 &&  FD_ISSET(fd, writefds)) {
			host_flag = 1;
			break;
		}
		if (exceptfds != 0 && FD_ISSET(fd, exceptfds)) {
			host_flag = 1;
			break;
		}
	}

	if (host_flag)
		return host_select(nfds, readfds, writefds, exceptfds, timeout);
	return rump___sysimpl_select(nfds, readfds, writefds,
				     exceptfds, timeout);
}
weak_alias(nuse_select, select);

int
nuse_epoll_create(int size)
{
	return rump___sysimpl_epoll_create(size);
}
weak_alias(nuse_epoll_create, epoll_create);

int
nuse_epoll_ctl(int epollfd, int op, int fd, struct epoll_event *event)
{
	return rump___sysimpl_epoll_ctl(epollfd, op, fd, event);
}
weak_alias(nuse_epoll_ctl, epoll_ctl);

int
nuse_epoll_wait(int epollfd, struct epoll_event *events,
		int maxevents, int timeout)
{
	return rump___sysimpl_epoll_wait(epollfd, events, maxevents, timeout);
}
weak_alias(nuse_epoll_wait, epoll_wait);


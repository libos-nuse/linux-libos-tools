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

#include "sim-assert.h"
#include "nuse-hostcalls.h"
#include "nuse.h"
#include "nuse-libc.h"
#include "nuse-sched.h"
#include "sim-init.h"
#include "sim.h"

extern struct SimExported *g_exported;
struct SimSocket;

#define weak_alias(name, aliasname)					\
	extern __typeof (name) aliasname __attribute__ ((weak, alias (# name)))
#define MSEC_PER_SEC	1000L
#define NSEC_PER_MSEC	1000000L
#define NSEC_PER_SEC	1000000000L

static inline __s64 timespec_to_ns(const struct timespec *ts)
{
	return ((__s64) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

/* FIXME: need to be configurable */
struct nuse_fd nuse_fd_table[1024];

/* epoll relates */
struct epoll_fd {
	struct epoll_fd *next;
	struct epoll_event *ev;
	int fd;
};


int nuse_socket(int domain, int type, int protocol)
{
	struct SimSocket *kernel_socket;
	int ret, real_fd;

	if (domain == AF_UNIX) {
		if (!host_socket) nuse_hostcall_init();
		real_fd = host_socket (domain, type, protocol);
		if (real_fd == -1)
			return real_fd;
		nuse_fd_table[real_fd].real_fd = real_fd;
		nuse_fd_table[real_fd].nuse_sock = NULL;
		return real_fd;
	}

	ret = g_exported->sock_socket(domain, type, protocol, &kernel_socket);
	if (ret < 0)
		errno = -ret;
	real_fd = host_open("/", O_RDONLY, 0);
	nuse_fd_table[real_fd].nuse_sock = malloc(sizeof(struct nuse_socket));
	memset(nuse_fd_table[real_fd].nuse_sock, 0, sizeof(struct nuse_socket));

	nuse_fd_table[real_fd].nuse_sock->kern_sock = kernel_socket;
	nuse_fd_table[real_fd].nuse_sock->refcnt++;
	nuse_fd_table[real_fd].real_fd = real_fd;

	return real_fd;
}
weak_alias(nuse_socket, socket);

int nuse_close(int fd)
{
	int ret = 0;

	if (!nuse_fd_table[fd].nuse_sock) {
		if (nuse_fd_table[fd].epoll_fd > 0) {
			free(nuse_fd_table[fd].epoll_fd);
			nuse_fd_table[fd].epoll_fd = NULL;
			return 0;
		} else if (nuse_fd_table[fd].real_fd > 0) {
			if (!host_close) nuse_hostcall_init();
			return host_close(nuse_fd_table[fd].real_fd);
		}
		return EBADF;
	}

	if (--nuse_fd_table[fd].nuse_sock->refcnt > 0) {
		goto end;
	}

	ret = g_exported->sock_close(nuse_fd_table[fd].nuse_sock->kern_sock);
	if (ret < 0)
		errno = -ret;

end:
	nuse_fd_table[fd].nuse_sock = 0;
	host_close(nuse_fd_table[fd].real_fd);
	return ret;
}
weak_alias(nuse_close, close);

ssize_t nuse_recvmsg(int fd, struct msghdr *msghdr, int flags)
{
	struct SimSocket *kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	ssize_t ret;

	if (nuse_fd_table[fd].nuse_sock->flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	ret = g_exported->sock_recvmsg(kernel_socket, msghdr, flags);
	if (ret < 0)
		errno = -ret;
	return ret;
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
	struct SimSocket *kernel_socket;
	ssize_t ret;

	if (!nuse_fd_table[fd].nuse_sock)
		return host_sendmsg(nuse_fd_table[fd].real_fd, msghdr, flags);

	kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	if (nuse_fd_table[fd].nuse_sock->flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	ret = g_exported->sock_sendmsg(kernel_socket, msghdr, flags);
	if (ret < 0)
		errno = -ret;
	return ret;
}
weak_alias(nuse_sendmsg, sendmsg);

int nuse_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen,
		  int flags)
{
	int err, datagrams;
	struct mmsghdr *entry;

	datagrams = 0;
	entry = msgvec;
	err = 0;

	while (datagrams < vlen) {
		err = nuse_sendmsg(fd,
				   (struct msghdr *)entry,
				   flags);
		if (err < 0)
			break;
		entry->msg_len = err;
		++entry;
		++datagrams;
	}

	/* We only return an error if no datagrams were able to be sent */
	if (datagrams != 0)
		return datagrams;

	return err;
}
weak_alias(nuse_sendmmsg, sendmmsg);
weak_alias(nuse_sendmmsg, __sendmmsg);

int nuse_getsockname(int fd, struct sockaddr *name, socklen_t *namelen)
{
	struct SimSocket *kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	int ret;

	ret = g_exported->sock_getsockname(kernel_socket, name, (int *)namelen);
	return ret;
}
weak_alias(nuse_getsockname, getsockname);

int nuse_getpeername(int fd, struct sockaddr *name, socklen_t *namelen)
{
	struct SimSocket *kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	int ret;

	ret = g_exported->sock_getsockname(kernel_socket, name, (int *)namelen);
	return ret;
}
weak_alias(nuse_getpeername, getpeername);

int nuse_bind(int fd, const struct sockaddr *name, socklen_t namelen)
{
	struct SimSocket *kernel_socket;
	int ret;

	if (!nuse_fd_table[fd].nuse_sock)
		return host_bind(nuse_fd_table[fd].real_fd, name, namelen);

	kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	ret = g_exported->sock_bind(kernel_socket, name, namelen);
	return ret;
}
weak_alias(nuse_bind, bind);

int nuse_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	struct SimSocket *kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	int ret;

	ret = g_exported->sock_connect(kernel_socket, addr, len,
				       nuse_fd_table[fd].nuse_sock->flags);
	return ret;
}
weak_alias(nuse_connect, connect);

int nuse_listen(int fd, int v1)
{
	struct SimSocket *kernel_socket;
	int retval;

	if (!nuse_fd_table[fd].nuse_sock)
		return host_listen(nuse_fd_table[fd].real_fd, v1);

	kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	retval = g_exported->sock_listen(kernel_socket, v1);
	return retval;
}
weak_alias(nuse_listen, listen);

#if 0
int lib_sock_shutdown(struct SimSocket *socket, int how)
{
	struct socket *sock = (struct socket *)socket;
	int retval = sock->ops->shutdown(sock, how);

	return retval;
}
#endif

int nuse_accept4(int fd, struct sockaddr *addr, int *addrlen, int flags)
{
	struct SimSocket *kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	struct SimSocket *new_socket = NULL;
	int retval, real_fd;

	retval = g_exported->sock_accept(kernel_socket, &new_socket, flags);
	if (retval < 0) {
		errno = -retval;
		free(new_socket);
		perror("accept err");
		return -1;
	}
	if (addr != 0) {
		retval = g_exported->sock_getpeername(new_socket, addr, (int *)addrlen);
		if (retval < 0) {
			errno = -retval;
			g_exported->sock_close(new_socket);
			perror("getpeername err");
			return -1;
		}
	}

	real_fd = host_open("/", O_RDONLY, 0);
	nuse_fd_table[real_fd].nuse_sock = malloc(sizeof(struct nuse_socket));
	memset(nuse_fd_table[real_fd].nuse_sock, 0, sizeof(struct nuse_socket));

	nuse_fd_table[real_fd].nuse_sock->kern_sock = new_socket;
	nuse_fd_table[real_fd].nuse_sock->refcnt++;
	nuse_fd_table[real_fd].real_fd = real_fd;
	return real_fd;
}
int nuse_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (!nuse_fd_table[fd].nuse_sock)
		return host_accept(nuse_fd_table[fd].real_fd, addr, addrlen);

	return nuse_accept4(fd, addr, (int *)addrlen,
			    nuse_fd_table[fd].nuse_sock->flags);
}
weak_alias(nuse_accept, accept);

ssize_t nuse_write(int fd, const void *buf, size_t count)
{
	if (!nuse_fd_table[fd].nuse_sock) {
		if (!host_write) nuse_hostcall_init();
		return host_write(nuse_fd_table[fd].real_fd, buf, count);
	}

	struct msghdr msg;
	struct iovec iov;

	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = count;
	iov.iov_base = (void *)buf;
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	return nuse_sendmsg(fd, &msg, 0);
}
weak_alias(nuse_write, write);

ssize_t nuse_writev(int fd, const struct iovec *iov, int count)
{
	if (!nuse_fd_table[fd].nuse_sock) {
		if (!host_writev) nuse_hostcall_init();
		return host_writev(nuse_fd_table[fd].real_fd, iov, count);
	}

	struct msghdr msg;

	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = (struct iovec *)iov;
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	return nuse_sendmsg(fd, &msg, 0);
}
weak_alias(nuse_writev, writev);

ssize_t nuse_sendto(int fd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, unsigned int addrlen)
{
	struct msghdr msg;
	struct iovec iov;
	ssize_t retval;

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = len;
	iov.iov_base = (void *)buf;
	msg.msg_name = (void *)dest_addr;
	msg.msg_namelen = addrlen;
	retval = nuse_sendmsg(fd, &msg, flags);
	return retval;
}
weak_alias(nuse_sendto, sendto);

ssize_t nuse_send(int fd, const void *buf, size_t len, int flags)
{
	return nuse_sendto(fd, buf, len, flags, 0, 0);
}
weak_alias(nuse_send, send);

ssize_t nuse_read(int fd, void *buf, size_t count)
{
	if (!nuse_fd_table[fd].nuse_sock) {
		if (!host_read) nuse_hostcall_init();
		return host_read(nuse_fd_table[fd].real_fd, buf, count);
	}

	struct msghdr msg;
	struct iovec iov;
	ssize_t retval;

	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = count;
	iov.iov_base = buf;
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	retval = nuse_recvmsg(fd, &msg, 0);
	return retval;
}
weak_alias(nuse_read, read);

#ifdef _K_SS_MAXSIZE
#define SOCK_MAX_ADDRESS_SIZE _K_SS_MAXSIZE
#else
#define SOCK_MAX_ADDRESS_SIZE 128
#endif
ssize_t nuse_recvfrom(int fd, void *buf, size_t len, int flags,
		      struct sockaddr *from, socklen_t *fromlen)
{
	uint8_t address[SOCK_MAX_ADDRESS_SIZE];
	struct msghdr msg;
	struct iovec iov;
	ssize_t retval;

	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = len;
	iov.iov_base = buf;
	msg.msg_name = address;
	msg.msg_namelen = SOCK_MAX_ADDRESS_SIZE;
	retval = nuse_recvmsg(fd, &msg, flags);
	if (retval != -1 && from != 0) {
		if (*fromlen < msg.msg_namelen) {
			errno = EINVAL;
			return -1;
		} else {
			*fromlen = msg.msg_namelen;
			memcpy(from, msg.msg_name, msg.msg_namelen);
		}
	}
	return retval;
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
	struct SimSocket *kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	int retval = g_exported->sock_setsockopt(kernel_socket, level, optname, optval,
					 optlen);
	if (retval < 0) {
		errno = -retval;
		return -1;
	}
	return retval;
}
weak_alias(nuse_setsockopt, setsockopt);

int nuse_getsockopt(int fd, int level, int optname,
		    void *optval, socklen_t *optlen)
{
	struct SimSocket *kernel_socket = nuse_fd_table[fd].nuse_sock->kern_sock;
	int retval = g_exported->sock_getsockopt(kernel_socket, level, optname, optval,
						 (int *)optlen);
	if (retval < 0) {
		errno = -retval;
		return -1;
	}
	return retval;
}
weak_alias(nuse_getsockopt, getsockopt);

int nuse_ioctl(int fd, int request, ...)
{
	va_list vl;
	char *argp;

	va_start(vl, request);
	argp = va_arg(vl, char *);
	va_end(vl);

	if (!nuse_fd_table[fd].nuse_sock) {
		if (!host_ioctl) nuse_hostcall_init();
		return host_ioctl(nuse_fd_table[fd].real_fd, request, argp);
	}

	return g_exported->sock_ioctl(nuse_fd_table[fd].nuse_sock->kern_sock, request, argp);
}
weak_alias(nuse_ioctl, ioctl);

int nuse_fcntl(int fd, int cmd, ... /* arg */ )
{
	va_list vl;
	int *argp;
	long err = -EINVAL;

	va_start(vl, cmd);
	argp = va_arg(vl, int *);
	va_end(vl);

	if (!nuse_fd_table[fd].nuse_sock) {
		if (!host_fcntl) nuse_hostcall_init();
		return host_fcntl(nuse_fd_table[fd].real_fd, cmd, argp);
	}

	/* nuse routine */
	switch (cmd) {
	case F_DUPFD:
		err = host_fcntl(nuse_fd_table[fd].real_fd, cmd, argp);
		if (err == -1) {
			return err;
		}
		nuse_fd_table[err].real_fd = err;
		nuse_fd_table[err].nuse_sock = nuse_fd_table[fd].nuse_sock;
		nuse_fd_table[err].epoll_fd = nuse_fd_table[fd].epoll_fd;
		nuse_fd_table[err].nuse_sock->refcnt++;

		break;
	case F_GETFL:
		return nuse_fd_table[fd].nuse_sock->flags;
		break;
	case F_SETFL:
		nuse_fd_table[fd].nuse_sock->flags = (intptr_t)argp;
		return 0;
		break;
	default:
		break;
	}
	return err;
}

int nuse_open(const char *pathname, int flags, ...)
{
	va_list vl;

	va_start(vl, flags);

	if (!host_open) nuse_hostcall_init();
	int real_fd = host_open(pathname, flags, va_arg(vl, mode_t));
	va_end(vl);

	if (real_fd < 0) {
		perror("open");
		return -1;
	}
	nuse_fd_table[real_fd].real_fd = real_fd;
	return real_fd;
}

int open64(const char *pathname, int flags, mode_t mode)
{
	if (!host_open64) nuse_hostcall_init();
	int real_fd = host_open64(pathname, flags, mode);

	/*  printf ("%d, %llu %s %s\n", nuse_fd_table[curfd].real_fd, curfd, pathname, __FUNCTION__); */
	if (real_fd < 0) {
		perror("open64");
		return -1;
	}
	nuse_fd_table[real_fd].real_fd = real_fd;
	return real_fd;
}

int pipe(int pipefd[2])
{
	if (!host_pipe) nuse_hostcall_init();
	int ret = host_pipe(pipefd);

	if (ret == -1)
		return ret;

	nuse_fd_table[pipefd[0]].real_fd = pipefd[0];
	nuse_fd_table[pipefd[1]].real_fd = pipefd[1];
	return ret;
}


/* From librumphijack/hijack.c */
struct pollarg {
	struct pollfd *pfds;
	nfds_t nfds;
	const struct timespec *ts;
	const sigset_t *sigmask;
	int pipefd;
	int errnum;
};

static void *
hostpoll(void *arg)
{
	struct pollarg *parg = arg;
	intptr_t rv;
	int to;

	to = parg->ts ? timespec_to_ns(parg->ts) / NSEC_PER_MSEC : -1;
	if (!host_poll) nuse_hostcall_init();
	rv = host_poll(parg->pfds, parg->nfds, to);
	if (rv == -1)
		parg->errnum = errno;
	lib_assert(write(parg->pipefd, &rv, sizeof(rv)) > 0);

	return (void *)rv;
}

/*
 * poll is easy as long as the call comes in the fds only in one
 * kernel.  otherwise its quite tricky...
 */

static int
do_host_nuse_poll(struct pollfd *fds, nfds_t nfds, struct timespec *ts)
{
	/* copied from librumphijack/hijack.c */
	struct pollfd *pfd_host = NULL, *pfd_rump = NULL;
	int rpipe[2] = {-1,-1}, hpipe[2] = {-1,-1};
	struct pollarg parg;
	void *trv_val;
	int sverrno = 0, rv_rump, rv_host, errno_rump, errno_host;
	pthread_t pt;
	nfds_t i;
	int rv;

	/*
	 * ok, this is where it gets tricky.  We must support
	 * this since it's a very common operation in certain
	 * types of software (telnet, netcat, etc).  We allocate
	 * two vectors and run two poll commands in separate
	 * threads.  Whichever returns first "wins" and the
	 * other kernel's fds won't show activity.
	 */
	rv = -1;

	/* allocate full vector for O(n) joining after call */
	pfd_host = malloc(sizeof(*pfd_host)*(nfds+1));
	if (!pfd_host)
		goto out;
	pfd_rump = malloc(sizeof(*pfd_rump)*(nfds+1));
	if (!pfd_rump) {
		goto out;
	}

	/*
	 * then, open two pipes, one for notifications
	 * to each kernel.
	 *
	 * At least the rump pipe should probably be
	 * cached, along with the helper threads.  This
	 * should give a microbenchmark improvement (haven't
	 * experienced a macro-level problem yet, though).
	 */
	if ((rv = pipe(rpipe)) == -1) {
		sverrno = errno;
	}
	if (rv == 0 && (rv = pipe(hpipe)) == -1) {
		sverrno = errno;
	}

	/* split vectors (or signal errors) */
	for (i = 0; i < nfds; i++) {
		int fd;

		fds[i].revents = 0;
		if (fds[i].fd == -1) {
			pfd_host[i].fd = -1;
			pfd_rump[i].fd = -1;
		} else if (nuse_fd_table[fds[i].fd].nuse_sock) {
			pfd_host[i].fd = -1;
			fd = fds[i].fd;
			if (fd == rpipe[0] || fd == rpipe[1]) {
				fds[i].revents = POLLNVAL;
				if (rv != -1)
					rv++;
			}
			pfd_rump[i].fd = fd;
			pfd_rump[i].events = fds[i].events;
		} else {
			pfd_rump[i].fd = -1;
			fd = fds[i].fd;
			if (fd == hpipe[0] || fd == hpipe[1]) {
				fds[i].revents = POLLNVAL;
				if (rv != -1)
					rv++;
			}
			pfd_host[i].fd = fd;
			pfd_host[i].events = fds[i].events;
		}
		pfd_rump[i].revents = pfd_host[i].revents = 0;
	}
	if (rv) {
		goto out;
	}

	pfd_host[nfds].fd = hpipe[0];
	pfd_host[nfds].events = POLLIN;
	pfd_rump[nfds].fd = rpipe[0];
	pfd_rump[nfds].events = POLLIN;

	/*
	 * then, create a thread to do host part and meanwhile
	 * do rump kernel part right here
	 */

	parg.pfds = pfd_host;
	parg.nfds = nfds+1;
	parg.ts = ts;
	/* parg.sigmask = sigmask; */
	parg.pipefd = rpipe[1];
	host_pthread_create(&pt, NULL, hostpoll, &parg);

	rv_rump = nuse_poll(pfd_rump, nfds+1, ts);
	errno_rump = errno;
	lib_assert(write(hpipe[1], &rv, sizeof(rv)) > 0);
	host_pthread_join(pt, &trv_val);
	rv_host = (int)(intptr_t)trv_val;
	errno_host = parg.errnum;

	/* strip cross-thread notification from real results */
	if (rv_host > 0 && pfd_host[nfds].revents & POLLIN) {
		rv_host--;
	}
	if (rv_rump > 0 && pfd_rump[nfds].revents & POLLIN) {
		rv_rump--;
	}

	/* then merge the results into what's reported to the caller */
	if (rv_rump > 0 || rv_host > 0) {
		/* SUCCESS */

		rv = 0;
		if (rv_rump > 0) {
			for (i = 0; i < nfds; i++) {
				if (pfd_rump[i].fd != -1)
					fds[i].revents
						= pfd_rump[i].revents;
			}
			rv += rv_rump;
		}
		if (rv_host > 0) {
			for (i = 0; i < nfds; i++) {
				if (pfd_host[i].fd != -1)
					fds[i].revents
						= pfd_host[i].revents;
			}
			rv += rv_host;
		}
		lib_assert(rv > 0);
		sverrno = 0;
	} else if (rv_rump == -1 || rv_host == -1) {
		/* ERROR */

		/* just pick one kernel at "random" */
		rv = -1;
		if (rv_host == -1) {
			sverrno = errno_host;
		} else if (rv_rump == -1) {
			sverrno = errno_rump;
		}
	} else {
		/* TIMEOUT */

		rv = 0;
		lib_assert(rv_rump == 0 && rv_host == 0);
	}

out:
	if (rpipe[0] != -1)
		host_close(rpipe[0]);
	if (rpipe[1] != -1)
		host_close(rpipe[1]);
	if (hpipe[0] != -1)
		host_close(hpipe[0]);
	if (hpipe[1] != -1)
		host_close(hpipe[1]);
	free(pfd_host);
	free(pfd_rump);
	errno = sverrno;

	return rv;
}

/* copied from librumphijack/hijack.c */
static void
checkpoll(struct pollfd *fds, nfds_t nfds, int *hostcall, int *rumpcall)
{
	nfds_t i;

	for (i = 0; i < nfds; i++) {
		if (fds[i].fd == -1)
			continue;

		if (nuse_fd_table[fds[i].fd].nuse_sock)
			(*rumpcall)++;
		else
			(*hostcall)++;
	}
}

struct poll_table_ref
{
  int ret;
  void *opaque;
};

int
nuse_poll(struct pollfd *fds, unsigned int nfds, struct timespec *end_time)
{
	struct poll_table_ref table, *current_table;
	struct poll_table_ref null_table = {0};
	int count = 0;
	int i, mask, timed_out = 0;

	struct NuseTask *task = (struct NuseTask *)rumpuser_curlwp();
	if (!task)
		task = lwp0;

	/* initialize all outgoing events. */
	for (i = 0; i < nfds; ++i)
		fds[i].revents = 0;

	table.opaque = NULL;
	current_table = &table;
	if (end_time && end_time->tv_sec == 0 &&
	    end_time->tv_nsec == 0) {
		current_table = NULL;
		timed_out = 1;
	}

	/* call (sim) kernel side */
	for (;;) {
		for (i = 0; i < nfds; ++i) {
			struct SimSocket *sock;

			/* host's fd */
			if (fds[i].fd == -1)
				continue;
			if (!nuse_fd_table[fds[i].fd].nuse_sock)
				continue;
			/* nuse's fd */
			sock = nuse_fd_table[fds[i].fd].nuse_sock->kern_sock;
			if (current_table) {
				current_table->ret = fds[i].events | POLLERR | POLLHUP;
				current_table->opaque = task->cv;
			}
			else
				current_table = &null_table;

			g_exported->sock_poll((struct SimSocket *)sock, current_table);

			mask = current_table->ret;
			mask &= (fds[i].events | POLLERR | POLLHUP);
			fds[i].revents = mask;
			if (mask) {
				count++;
				current_table = NULL;
			}
		}

		current_table = NULL;
		if (count || timed_out) {
			break;
		}

		if (timed_out == 0) {
			/* infinite wait */
			if (end_time == NULL) {
				rumpuser_mutex_enter(task->mtx);
				rumpuser_cv_wait(task->cv, task->mtx);
				rumpuser_mutex_exit(task->mtx);
			}
			/* sleeped wait */
			else {
				rumpuser_mutex_enter(task->mtx);
				rumpuser_cv_timedwait(task->cv, task->mtx, 
						      end_time->tv_sec,
						      end_time->tv_nsec);
				rumpuser_mutex_exit(task->mtx);
			}
			timed_out = 1;
		}
	} /* for loop */

	g_exported->sock_pollfreewait(table.opaque);
	return count;
}

int
__nuse_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	struct timespec *to = NULL, end_time;
	int hostcall = 0, rumpcall = 0;
	int count;

	if (timeout >= 0) {
		end_time.tv_sec = timeout / MSEC_PER_SEC;
		end_time.tv_nsec = NSEC_PER_MSEC * (timeout % MSEC_PER_SEC);
		to = &end_time;
	}

	checkpoll(fds, nfds, &hostcall, &rumpcall);
	if (hostcall && rumpcall) {
		/* this is the case to write carefully between host and nuse */
		/* see rump/hijack.c for more detail  */
		count = do_host_nuse_poll(fds, nfds, to);
	}
	else {
		if (hostcall) {
			count = host_poll(fds, nfds, timeout);
		}
		else {
			count = nuse_poll(fds, nfds, to);
		}
	}

	return count;
}
weak_alias (__nuse_poll, __poll);

int
select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	struct pollfd pollFd[nfds];
	int fd;

	memset(pollFd, 0, sizeof(struct pollfd) * nfds);

	if (nfds == -1) {
		errno = EINVAL;
		return -1;
	}
	if (readfds == 0 && writefds == 0 && exceptfds == 0) {
		errno = EINVAL;
		return -1;
	}
	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_usec < 0) {
			errno = EINVAL;
			return -1;
		}
	}

	for (fd = 0; fd < nfds; fd++) {
		int event = 0;

		if (readfds != 0 && FD_ISSET(fd, readfds))
			event |= POLLIN;
		if (writefds != 0 &&  FD_ISSET(fd, writefds))
			event |= POLLOUT;
		if (exceptfds != 0 && FD_ISSET(fd, exceptfds))
			event |= POLLPRI;

		pollFd[fd].events = event;
		pollFd[fd].revents = 0;

		if (event) {
			if (!nuse_fd_table[fd].nuse_sock) {
				errno = EBADF;
				return -1;
			}
			pollFd[fd].fd = fd;
		}
		else {
			pollFd[fd].fd = -1;
		}
	}

	/* select(2): */
	/* Some  code  calls  select() with all three sets empty, nfds zero,
	   and a non-NULL timeout as a fairly portable way to sleep with 
	   subsecond precision. */
	/* 130825: this condition will be passed by dce_poll () */

	int to_msec = -1;

	if (timeout)
		to_msec = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;

	int ret = poll(pollFd, nfds, to_msec);

	if (readfds)
		FD_ZERO(readfds);
	if (writefds)
		FD_ZERO(writefds);
	if (exceptfds)
		FD_ZERO(exceptfds);

	if (ret > 0) {
		ret = 0;
		for (fd = 0; fd < nfds; fd++) {
			if (readfds &&
			    ((POLLIN & pollFd[fd].revents) ||
			     (POLLHUP & pollFd[fd].revents)
			     || (POLLERR & pollFd[fd].revents))) {
				FD_SET(pollFd[fd].fd, readfds);
				ret++;
			}
			if (writefds && (POLLOUT & pollFd[fd].revents)) {
				FD_SET(pollFd[fd].fd, writefds);
				ret++;
			}
			if (exceptfds && (POLLPRI & pollFd[fd].revents)) {
				FD_SET(pollFd[fd].fd, exceptfds);
				ret++;
			}
		}
	}
	return ret;
}

int
nuse_epoll_create(int size)
{
	struct epoll_fd *epfd = malloc(sizeof(struct epoll_fd));
	int real_fd;

	memset(epfd, 0, sizeof(struct epoll_fd));
	real_fd = host_open("/", O_RDONLY, 0);
	nuse_fd_table[real_fd].real_fd = real_fd;
	nuse_fd_table[real_fd].epoll_fd = epfd;
	return real_fd;
}

int
nuse_epoll_ctl(int epollfd, int op, int fd, struct epoll_event *event)
{
	struct epoll_fd *prev = NULL, *epfd = nuse_fd_table[epollfd].epoll_fd;

	if (!epfd)
		return EBADF;

	struct epoll_event *ev;

	switch (op) {
	case EPOLL_CTL_ADD:
		ev = (struct epoll_event *)malloc(sizeof(struct epoll_event));
		memset(ev, 0, sizeof(struct epoll_event));
		memcpy(ev, event, sizeof(struct epoll_event));

		if (!epfd->ev) {
			epfd->ev = ev;
			epfd->fd = fd;
		} else {
			prev = epfd;
			while (epfd->next) {
				prev = epfd;
				epfd = epfd->next;
			}

			epfd->next = malloc(sizeof(struct epoll_fd));
			memset(epfd->next, 0, sizeof(struct epoll_fd));
			epfd->next->ev = ev;
			epfd->next->fd = fd;
		}
		break;
	case EPOLL_CTL_MOD:
		while (epfd && epfd->fd != fd)
			epfd = epfd->next;
		ev = epfd->ev;
		memcpy(ev, event, sizeof(struct epoll_event));
		epfd->fd = fd;
		break;
	case EPOLL_CTL_DEL:
		while (epfd && epfd->fd != fd) {
			prev = epfd;
			epfd = epfd->next;
		}
		if (!epfd) {
			printf("NUSE: no fd found for EPOLL_CTL_DEL (fd=%d)\n", fd);
			errno = ENOENT;
			return -1;
		}
		ev = epfd->ev;
		epfd->fd = -1;
		free(ev);
		if (prev) {
			prev->next = epfd->next;
			epfd = prev;
		}

		break;
	default:
		break;
	}

	return 0;
}

int
nuse_epoll_wait(int epollfd, struct epoll_event *events,
		int maxevents, int timeout)
{
	struct epoll_fd *cur, *epfd = nuse_fd_table[epollfd].epoll_fd;

	if (!epfd)
		return EBADF;

	struct pollfd pollFd[maxevents];
	int j = 0;

	memset(pollFd, 0, sizeof(struct pollfd) * maxevents);
	for (j = 0; j < maxevents; j++) {
		pollFd[j].fd = -1;
	}
	j = 0;

	for (cur = epfd; cur && cur->ev; cur = cur->next) {
		struct epoll_event *ev = cur->ev;
		int pevent = 0;
		if (ev->events & EPOLLIN)
			pevent |= POLLIN;
		if (ev->events & EPOLLOUT)
			pevent |= POLLOUT;

		pollFd[j].events = pevent;
		pollFd[j].fd = cur->fd;
		pollFd[j++].revents = 0;
	}

	int pollRet = poll(pollFd, maxevents, timeout);
	if (pollRet > 0) {
		pollRet = 0;
		/* FIXME: c10k... far fast */
		for (j = 0; j < maxevents; j++) {
			int fd = pollFd[j].fd;
			struct epoll_event *rev = NULL;

			for (cur = epfd; cur && epfd->ev; cur = cur->next) {
				rev = cur->ev;
				if (cur->fd == fd)
					break;
			}

			if ((POLLIN & pollFd[j].revents) ||
			    (POLLHUP & pollFd[j].revents)
			    || (POLLERR & pollFd[j].revents)) {
				memcpy(events, rev, sizeof(struct epoll_event));
				events->events = pollFd[j].revents;
				printf("epoll woke up for read with %d\n", fd);
				pollRet++;
				events++;
			}
			if (POLLOUT & pollFd[j].revents) {
				memcpy(events, rev, sizeof(struct epoll_event));
				events->events = pollFd[j].revents;
				/* *events = *epollFd->evs[fd]; */
				/* events->data.fd = fd; */
				printf("epoll woke up for write with %d\n", fd);
				pollRet++;
				events++;
			}
			if (POLLPRI & pollFd[j].revents) {
				memcpy(events, rev, sizeof(struct epoll_event));
				events->events = pollFd[j].revents;
				printf("epoll woke up for other with %d\n", fd);
				/* *events = *epollFd->evs[fd]; */
				/* events->data.fd = fd; */
				pollRet++;
				events++;
			}

		}
	}

	return pollRet;
}


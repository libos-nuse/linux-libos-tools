/*
 * Network stack in userspace (NUSE) for POSIX userspace backend
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 */

#ifndef NUSE_H
#define NUSE_H

struct SimDevice;
extern struct SimExported *g_exported;

/* nuse.c */
int nuse_socket(int domain, int type, int protocol);
int nuse_ioctl(int fd, int request, ...);
int nuse_close(int fd);
void nuse_dev_rx(struct SimDevice *dev, char *buf, int size);

/* rump.c */
int rump_init(void);
void rump_exit(void);

#endif /* NUSE_H */

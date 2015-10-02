/*
 * Rump hypercall interface for Linux
 */

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>

#include <rump/rumpuser_port.h>
#include <rump/rump.h> /* XXX: for rfork flags */
#include <rump/rumpuser.h>

#include "generated/utsrelease.h"
#include "generated/compile.h"
#include "nuse.h"

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
rump_init_server(const char *url)
{

	setenv("RUMP_SERVER", url, 1);
	nuse_syscall_proxy_init();

	return 0;
}

int
rump_init(void)
{
//	nuse_init();
	return 0;
}

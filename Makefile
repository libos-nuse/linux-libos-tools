include Makefile.include

NUSE_LIB=libnuse-linux-$(KERNELVERSION).so
SIM_LIB=libsim-linux-$(KERNELVERSION).so
KERNEL_LIB=liblinux-$(KERNELVERSION).so
RUMP_HIJACK_LIB=libnuse-hijack.so
RUMP_CLIENT_LIB=librumpclient.so
RUMP_SERVER_LIB=librumpserver.so
LIBOS_DIR=..
srctree=$(LIBOS_DIR)/../../

CC=gcc

all: $(NUSE_LIB) $(SIM_LIB) $(RUMP_HIJACK_LIB) $(RUMP_CLIENT_LIB)

clean:
	$(call QUIET_CLEAN, NUSE) rm -f *.o lib*.so
	$(call QUIET_CLEAN, RUMP) $(MAKE) clean -s -f Makefile.rump
#	$(MAKE) clean -f Makefile.dpdk

# vif extensions
NUSE_SRC=""

NETMAP?=no
DPDK?=no

dpdk:
ifeq ($(DPDK), yes)
	$(QUIET_GEN) git submodule init && git submodule update dpdk
endif

netmap:
ifeq ($(NETMAP), yes)
	$(QUIET_GEN) git submodule init && git submodule update netmap
endif

# sources and objects
NUSE_SRC=\
nuse-fiber.c nuse-vif.c nuse-hostcalls.c nuse-config.c \
nuse-vif-rawsock.c nuse-vif-tap.c nuse-vif-pipe.c nuse-glue.c nuse.c

ifeq "$(DPDK)" "yes"
	include Makefile.dpdk
	DPDK_LDFLAGS=-L$(RTE_SDK)/$(RTE_TARGET)/lib nuse-vif-dpdk.o $(DPDK_LDLIBS)
	NUSE_SRC+=nuse-vif-dpdk.c
endif

ifeq "$(NETMAP)" "yes"
	NUSE_SRC+=nuse-vif-netmap.c
	CFLAGS+= -Inetmap/sys
endif


SIM_SRC=sim.c

SIM_OBJ=$(addsuffix .o,$(basename $(SIM_SRC)))
NUSE_OBJ=$(addsuffix .o,$(basename $(NUSE_SRC)))
# FIXME: possibly remove nuse-poll.c from $(ARCH_DIR)/Makefile and built in this Makefile
KERNEL_OBJS_SIM=$(addprefix $(srctree)/, $(filter-out arch/lib/nuse-poll.o, $(OBJS)))

ALL_OBJS+=$(SIM_OBJ) $(NUSE_OBJ)

# build flags
LDFLAGS_NUSE = -shared -nodefaultlibs -L. -lrumpserver -ldl -lpthread -lrt
LDFLAGS_SIM = -shared -nodefaultlibs -g3 -Wl,-O1 -Wl,-T$(LIBOS_DIR)/linker.lds $(covl_$(COV))
CFLAGS+= -Wall -fPIC -g3 -I. -I$(LIBOS_DIR)/include


export CFLAGS srctree LIBOS_DIR

# build target
%.o : %.c Makefile netmap
	$(QUIET_CC) $(CC) $(CFLAGS) -c $<

# order of $(dpdkl_$(DPDK)) matters...
$(NUSE_LIB): $(DPDK_OBJ) $(NUSE_OBJ) $(RUMP_SERVER_LIB) $(srctree)/$(KERNEL_LIB) Makefile
	$(QUIET_LINK) $(CC) -Wl,--whole-archive $(dpdkl_$(DPDK)) $(NUSE_OBJ) $(LDFLAGS_NUSE) -o $@ ;\
	ln -s -f $(NUSE_LIB) libnuse-linux.so ;\
	ln -s -f ./nuse.sh ./nuse

$(SIM_LIB): $(SIM_OBJ) $(srctree)/$(KERNEL_LIB) Makefile
	$(QUIET_LINK) $(CC) -Wl,--whole-archive $(SIM_OBJ) $(KERNEL_OBJS_SIM) $(LDFLAGS_SIM) -o $@; \
	ln -s -f $(SIM_LIB) libsim-linux.so

$(RUMP_CLIENT_LIB): Makefile.rump Makefile FORCE
	$(Q) $(MAKE) $(PRINT_DIR) -f Makefile.rump $@

$(RUMP_HIJACK_LIB): $(RUMP_CLIENT_LIB) Makefile.rump Makefile FORCE
	$(Q) $(MAKE) $(PRINT_DIR) -f Makefile.rump $@

$(RUMP_SERVER_LIB): Makefile.rump Makefile FORCE
	$(Q) $(MAKE) $(PRINT_DIR) -f Makefile.rump $@

FORCH:
.PHONY: clean FORCE netmap
.NOTPARALLEL : $(RUMP_SERVER_LIB) $(RUMP_CLIENT_LIB) $(RUMP_HIJACK_LIB)

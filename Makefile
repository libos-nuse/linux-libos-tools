include Makefile.include

NUSE_LIB=libnuse-linux-$(KERNELVERSION).so
NUSE_SLIB=libnuse-linux.a
SIM_LIB=libsim-linux-$(KERNELVERSION).so
KERNEL_LIB=liblinux-$(KERNELVERSION).so

LIBOS_DIR=..
srctree=$(LIBOS_DIR)/../../

RUMP_PREFIX?=$(srctree)/../obj/dest.stage
RUMP_INCLUDE=$(RUMP_PREFIX)/usr/include
RUMP_LIB=$(RUMP_PREFIX)/usr/lib

CC=gcc
dot-target = $(dir $@).$(notdir $@)
depfile = $(dot-target).d

all: $(NUSE_LIB) $(NUSE_SLIB) $(SIM_LIB)

clean:
	$(call QUIET_CLEAN, nuse) rm -f $(ALL_OBJS) lib*.so $(DEPS)

# vif extensions
NUSE_SRC=""

NETMAP?=no
DPDK?=no

dpdk/build/lib/libintel_dpdk.a:
ifeq ($(DPDK), yes)
	$(QUIET_GEN) git submodule init && git submodule update dpdk
	$(error "Execute the DPDK build script 'dpdk-sdk-build.sh' at the arch/lib/tools directory")
endif

netmap:
ifeq ($(NETMAP), yes)
	$(QUIET_GEN) git submodule init && git submodule update netmap
endif

# sources and objects
NUSE_SRC=
ifeq "$(DPDK)" "yes"
	include Makefile.dpdk
	DPDK_LDFLAGS=-L$(RTE_SDK)/$(RTE_TARGET)/lib
endif

ifeq "$(NETMAP)" "yes"
	NUSE_SRC+=nuse-vif-netmap.c
	CFLAGS+= -Inetmap/sys
endif

NUSE_SRC+=\
nuse-vif.c nuse-hostcalls.c nuse-config.c \
nuse-vif-rawsock.c nuse-vif-tap.c nuse-vif-pipe.c nuse.c \
nuse-sched.c $(LIBOS_DIR)/rump_syscalls.c rump.c nuse-glue.c


SIM_SRC=sim.c

SIM_OBJ=$(addsuffix .o,$(basename $(SIM_SRC)))
NUSE_OBJ=$(addsuffix .o,$(basename $(NUSE_SRC)))
KERNEL_OBJS_SIM=$(addprefix $(srctree)/, $(OBJS))
ALL_OBJS+=$(SIM_OBJ) $(NUSE_OBJ)

# build flags
LDFLAGS_NUSE = -shared -nodefaultlibs -L. -ldl -lpthread -lrt $(DPDK_LDFLAGS) -Wl,-z,lazy
LDFLAGS_SIM = -shared -nodefaultlibs -g3 -Wl,-O1 -Wl,-T$(LIBOS_DIR)/linker.lds $(covl_$(COV))
LDFLAGS_NUSE+= -Wl,-rpath=${RUMP_LIB} -L${RUMP_LIB} -lrumpuser
CFLAGS+= -Wp,-MD,$(depfile) -Wall -Werror -fno-stack-protector -U_FORTIFY_SOURCE -fPIC -g3 -I. -I$(LIBOS_DIR)/include
CFLAGS+= -I${RUMP_INCLUDE} -DLIBRUMPUSER -I./include/ $(klibc_$(KLIBC))
export CFLAGS srctree LIBOS_DIR

DEPS=$(addprefix ./.,$(addsuffix .o.d,$(basename $(NUSE_SRC))))
DEPS+=$(addprefix ./.,$(addsuffix .o.d,$(basename $(SIM_SRC))))
-include $(DEPS)

# build target
%.o : %.c Makefile
	$(QUIET_CC) $(CC) $(CFLAGS) -c $< -o $@ || exit -1;\
	${NM} -go $@ | awk ' \
	$$NF!~/^'${_PQ}'(${EXP_SYMRENAME})/ \
	{s=$$NF;sub(/^'${_PQ}'/, "&rumpns_", s); print $$NF, s}'\
	| sort | uniq  > $@.renametab; \
	objcopy --preserve-dates --redefine-syms $@.renametab $@; \
	rm -f $@.renametab

# order of $(dpdkl_$(DPDK)) matters...
$(NUSE_LIB): $(DPDK_OBJ) $(NUSE_OBJ) $(srctree)/$(KERNEL_LIB) Makefile $(RUMP_LIB)
	$(QUIET_LINK) $(CC) -Wl,--whole-archive $(dpdkl_$(DPDK)) $(NUSE_OBJ) $(LDFLAGS_NUSE) -o $@
	@ln -s -f $(NUSE_LIB) libnuse-linux.so
	@ln -s -f ./nuse.sh ./nuse

$(NUSE_SLIB): $(NUSE_LIB)
	$(QUIET_AR) rm -f libnuse-linux.a ; $(AR) cru $@ $(DPDK_OBJ) $(NUSE_OBJ)

$(SIM_LIB): $(SIM_OBJ) $(srctree)/$(KERNEL_LIB) Makefile
	$(QUIET_LINK) $(CC) -Wl,--whole-archive $(SIM_OBJ) $(LDFLAGS_SIM) -o $@ #$(KERNEL_OBJS_SIM)
	@ln -s -f $(SIM_LIB) libsim-linux.so

FORCH:
.PHONY: clean FORCE
.NOTPARALLEL :

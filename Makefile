NUSE_LIB=liblinux-nuse-$(KERNELVERSION).so
SIM_LIB=liblinux-sim-$(KERNELVERSION).so
LIB_USER_TOOL_DIR=$(ARCH_DIR)/tools

-include $(LIB_USER_TOOL_DIR)/Makefile.rump

# vif extensions
NUSE_USPACE_SRC=""
ifdef CONFIG_LIB_NUSE_DPDK
	include $(LIB_USER_TOOL_DIR)/Makefile.dpdk
	DPDK_LDFLAGS=-L$(RTE_SDK)/$(RTE_TARGET)/lib $(ARCH_DIR)/nuse-vif-dpdk.o $(DPDK_LDLIBS)
	NUSE_USPACE_SRC+=nuse-vif-dpdk.c
	git submodule update dpdk --init
endif

ifdef CONFIG_LIB_NUSE_NETMAP
	NUSE_USPACE_SRC+=nuse-vif-netmap.c
	git submodule update netmap --init
endif

#obj-$(CONFIG_LIB_NUSE_NETMAP)          += nuse-vif-netmap.o
#obj-$(CONFIG_LIB_NUSE_DPDK)            += nuse-vif-dpdk.o

# sources and objects
NUSE_USPACE_SRC=\
nuse-fiber.c nuse-vif.c nuse-hostcalls.c nuse-config.c \
nuse-vif-rawsock.c nuse-vif-tap.c nuse-vif-pipe.c nuse-glue.c nuse.c

SIM_SRC=sim.c

SIM_OBJ=$(addprefix $(LIB_USER_TOOL_DIR)/,$(addsuffix .o,$(basename $(SIM_SRC))))
NUSE_USPACE_OBJ=$(addprefix $(LIB_USER_TOOL_DIR)/,$(addsuffix .o,$(basename $(NUSE_USPACE_SRC))))

ALL_OBJS+=$(SIM_OBJ) $(NUSE_USPACE_OBJ)

# build flags
LDFLAGS_NUSE = -shared -nodefaultlibs -L$(srctree)/ -llinux -ldl -lpthread -lrt
LDFLAGS_SIM = -shared -nodefaultlibs -L$(srctree)/ -llinux

# build target

# XXX: no idea how to handle these exception cleanly..
quiet_cmd_ccusp = CC   $@
      cmd_ccusp = mkdir -p $(dir $@);	\
		$(CC) $(CFLAGS_USPACE) -c $< -o $@

$(NUSE_USPACE_OBJ): %.o : %.c
	$(call if_changed,ccusp)

quiet_cmd_linknuse = LIBNUSE	$@
      # order of $(dpdkl_$(DPDK)) matters...
      cmd_linknuse = $(CC) -Wl,--whole-archive $(dpdkl_$(DPDK)) $(NUSE_USPACE_OBJ) $(RUMPS_OBJ) $(LDFLAGS_NUSE) -o $@; \
		     ln -s -f $(NUSE_LIB) liblinux-nuse.so; \
		     ln -s -f $(LIB_USER_TOOL_DIR)/nuse.sh ./nuse

quiet_cmd_linksim = LIBSIM	$@
      cmd_linksim = $(CC) -Wl,--whole-archive $(SIM_OBJ) $(LDFLAGS) $(LDFLAGS_SIM) -o $@; \
		    ln -s -f $(SIM_LIB) liblinux-sim.so

$(NUSE_LIB):$(LIB_USER_TOOL_DIR)/rump $(DPDK_OBJ) $(NUSE_USPACE_OBJ) $(RUMPS_OBJ) $(KERNEL_LIB) $(ARCH_DIR)/linker.lds
	$(call if_changed,linknuse)

$(SIM_LIB): $(SIM_OBJ) $(KERNEL_LIB) $(ARCH_DIR)/linker.lds
	$(call if_changed,linksim)

%.o:%.c
	$(call if_changed,cc)

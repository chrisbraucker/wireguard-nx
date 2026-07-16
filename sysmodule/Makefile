#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

TOPDIR ?= $(CURDIR)
HOST_ONLY_GOALS := test test-sanitize
HOST_ONLY_BUILD := $(strip $(filter $(HOST_ONLY_GOALS),$(MAKECMDGOALS)))

ifeq ($(HOST_ONLY_BUILD),)
ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>/devkitpro")
endif

include $(DEVKITPRO)/libnx/switch_rules
include $(TOPDIR)/lib/Atmosphere-libs/config/templates/stratosphere.mk
endif

#---------------------------------------------------------------------------------
# TARGET is the name of the output
# BUILD is the directory where object files & intermediate files will be placed
# SOURCES is a list of directories containing source code
# DATA is a list of directories containing data files
# INCLUDES is a list of directories containing header files
# EXEFS_SRC is the optional input directory containing data copied into exefs, if anything this normally should only contain "main.npdm".
#---------------------------------------------------------------------------------
TARGET		:=	wireguard-nx
BUILD		:=	build
OUTDIR		:=	out
TITLE_ID	:=	010000000000EAD0
DISTDIR		:=	$(OUTDIR)/atmosphere/contents/$(TITLE_ID)
DATA		:=	data
RESOURCES	:=	res
SOURCES		+=	src src/runtime src/platform/horizon src/wireguard src/wireguard/crypto
INCLUDES	+=	../common/include \
			src \
			src/platform/horizon \
			$(TOPDIR)/lib/Atmosphere-libs/libstratosphere/include \
			$(TOPDIR)/lib/Atmosphere-libs/libvapours/include
LIBNAMES	:= Atmosphere-libs/libstratosphere

HOST_CXX	?= g++
HOST_CC		?= cc
HOST_TEST_CXXFLAGS := -std=c++23 -Wall -Wextra -Wpedantic -Werror
HOST_TEST_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror
HOST_TEST_DIR	:= $(OUTDIR)/host-test
HOST_TEST_TARGET := $(HOST_TEST_DIR)/wireguard-host-test
HOST_SANITIZE_DIR := $(OUTDIR)/host-test-sanitize
HOST_SANITIZE_TARGET := $(HOST_SANITIZE_DIR)/wireguard-host-test
HOST_TEST_CPP_SOURCES := \
	src/runtime/endpoint_resolver.cpp \
	src/runtime/peer_runtime.cpp \
	src/runtime/runtime_coordinator.cpp \
	src/runtime/udp_binding.cpp \
	src/wireguard/messages.cpp \
	src/wireguard/dispatch.cpp \
	src/wireguard/index_allocator.cpp \
	src/wireguard/session.cpp \
	src/wireguard/data.cpp \
	src/wireguard/inner_packet.cpp \
	src/wireguard/handshake.cpp \
	src/wireguard/timers.cpp \
	src/wireguard/timer_coordinator.cpp \
	src/wireguard/peer.cpp \
	src/wireguard/peer_controller.cpp \
	src/wireguard/device.cpp \
	src/wireguard/debug_probe.cpp \
	src/wireguard/crypto/primitives.cpp \
	test/host/host_stubs.cpp \
	test/host/legacy_self_tests.cpp \
	test/host/protocol_tests.cpp \
	test/host/main.cpp
HOST_TEST_C_SOURCES := src/wireguard/crypto/monocypher.c
HOST_TEST_HEADERS := $(shell find $(TOPDIR)/test/host $(TOPDIR)/src/runtime $(TOPDIR)/src/wireguard $(TOPDIR)/../common/include -type f -name '*.hpp')
HOST_TEST_INCLUDES := \
	-I$(CURDIR)/test/host \
	-I$(CURDIR)/test/host/include \
	-I$(CURDIR)/../common/include \
	-I$(CURDIR)/src

#---------------------------------------------------------------------------------
# version control constants
#---------------------------------------------------------------------------------
APP_VERSION		:= 0.0.1-dev
BUILD_ID		:= $(shell git describe --always --dirty 2>/dev/null || echo "unknown")
BUILD_ID_HEADER		:= $(TOPDIR)/$(BUILD)/build_id.hpp

#---------------------------------------------------------------------------------
# options for code generation
#---------------------------------------------------------------------------------
DEFINES	+=	-DDISABLE_IPC -D__SWITCH__ \
	-DTARGET="\"$(TARGET)\"" \
	-DVERSION="\"$(APP_VERSION)\""

CFLAGS	+= $(INCLUDE) -Wno-unused-result

CXXFLAGS	+= $(CFLAGS) -std=c++23 -Werror=frame-larger-than=8192

#---------------------------------------------------------------------------------
# list of directories containing libraries, this must be the top level containing
# include and lib
#---------------------------------------------------------------------------------
LIBDIRS	+= $(foreach lib,$(LIBNAMES),$(TOPDIR)/lib/$(lib))

#---------------------------------------------------------------------------------
# no real need to edit anything past this point unless you need to add additional
# rules for different file extensions
#---------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#---------------------------------------------------------------------------------

export OUTPUT	:=	$(CURDIR)/$(OUTDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)

export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
			$(foreach dir,$(DATA),$(CURDIR)/$(dir))

export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES	:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
BINFILES	:=	$(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.*)))

#---------------------------------------------------------------------------------
# use CXX for linking C++ projects, CC for standard C
#---------------------------------------------------------------------------------
ifeq ($(strip $(CPPFILES)),)
#---------------------------------------------------------------------------------
	export LD	:=	$(CC)
#---------------------------------------------------------------------------------
else
#---------------------------------------------------------------------------------
	export LD	:=	$(CXX)
#---------------------------------------------------------------------------------
endif
#---------------------------------------------------------------------------------

export OFILES 	:=	$(addsuffix .o,$(BINFILES)) $(OFILES_SRC) \
			$(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			$(foreach dir,$(AMS_LIBDIRS),-I$(dir)/include) \
			-I$(CURDIR)/$(BUILD)

export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib)\
					$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/lib) \
					$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/$(ATMOSPHERE_LIBRARY_DIR))

export BUILD_EXEFS_SRC := $(TOPDIR)/$(EXEFS_SRC)

export APP_JSON := $(TOPDIR)/res/module.json

.PHONY	: $(BUILD) clean clean-libs clean-build all libs dist test test-sanitize prepare-build-id

#---------------------------------------------------------------------------------
all	: $(BUILD)

dist	: $(BUILD)
	@[ -d $(DISTDIR)/flags ] || mkdir -p $(DISTDIR)/flags
	@cp $(OUTDIR)/$(TARGET).nsp $(DISTDIR)/exefs.nsp
	@printf '{\n  "name": "WireGuard-NX",\n  "tid": "$(TITLE_ID)",\n  "requires_reboot": false\n}\n' > $(DISTDIR)/toolbox.json
	@: > $(DISTDIR)/flags/boot2.flag
	@echo "prepared Atmosphere layout in $(DISTDIR)"

test: $(HOST_TEST_TARGET)
	@$(HOST_TEST_TARGET)

test-sanitize: $(HOST_SANITIZE_TARGET)
	@ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 $(HOST_SANITIZE_TARGET)

$(HOST_TEST_TARGET): Makefile $(HOST_TEST_CPP_SOURCES) $(HOST_TEST_C_SOURCES) $(HOST_TEST_HEADERS)
	@[ -d $(HOST_TEST_DIR) ] || mkdir -p $(HOST_TEST_DIR)
	@$(HOST_CC) $(HOST_TEST_CFLAGS) -I$(CURDIR)/src/wireguard/crypto -c $(CURDIR)/src/wireguard/crypto/monocypher.c -o $(HOST_TEST_DIR)/monocypher.o
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_CPP_SOURCES)) $(HOST_TEST_DIR)/monocypher.o -o $(HOST_TEST_TARGET)

$(HOST_SANITIZE_TARGET): Makefile $(HOST_TEST_CPP_SOURCES) $(HOST_TEST_C_SOURCES) $(HOST_TEST_HEADERS)
	@[ -d $(HOST_SANITIZE_DIR) ] || mkdir -p $(HOST_SANITIZE_DIR)
	@$(HOST_CC) $(HOST_TEST_CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer -I$(CURDIR)/src/wireguard/crypto -c $(CURDIR)/src/wireguard/crypto/monocypher.c -o $(HOST_SANITIZE_DIR)/monocypher.o
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_CPP_SOURCES)) $(HOST_SANITIZE_DIR)/monocypher.o -o $(HOST_SANITIZE_TARGET)

libs	:
	@$(foreach lib,$(LIBNAMES),$(MAKE) --no-print-directory -C $(TOPDIR)/lib/$(lib) && ) true

prepare-build-id:
	@[ -d $(dir $(BUILD_ID_HEADER)) ] || mkdir -p $(dir $(BUILD_ID_HEADER))
	@printf '#pragma once\n\nnamespace wgnx {\ninline constexpr char BuildId[] = "$(BUILD_ID)";\n} // namespace wgnx\n' > $(BUILD_ID_HEADER).tmp
	@if ! cmp -s $(BUILD_ID_HEADER).tmp $(BUILD_ID_HEADER); then \
		mv $(BUILD_ID_HEADER).tmp $(BUILD_ID_HEADER); \
	else \
		rm $(BUILD_ID_HEADER).tmp; \
	fi

$(LIBNAMES)	:
	@echo $@

$(BUILD)	: libs prepare-build-id
	@[ -d $@ ] || mkdir -p $@
	@[ -d $(OUTDIR) ] || mkdir -p $(OUTDIR)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

#---------------------------------------------------------------------------------
clean-libs	:
	@echo clean libs $(LIBNAMES) ...
	@$(foreach lib,$(LIBNAMES),$(MAKE) -C $(TOPDIR)/lib/$(lib) clean && ) true

clean-build	:
	@echo clean build ...
	@rm -fr $(BUILD) $(TARGET).kip $(TARGET).nsp $(TARGET).npdm $(TARGET).nso $(TARGET).elf $(OUTDIR)

clean	: clean-libs clean-build


#---------------------------------------------------------------------------------
else
.PHONY	:	all

DEPENDS		:=	$(OFILES:.o=.d)

#---------------------------------------------------------------------------------
# main targets
#---------------------------------------------------------------------------------

all	: $(OUTPUT).nsp

$(OUTPUT).nsp	: $(OUTPUT).nso $(OUTPUT).npdm
$(OUTPUT).nso :	$(OUTPUT).elf

$(OUTPUT).elf	: $(OFILES)

$(OFILES)	: $(ATMOSPHERE_LIBRARIES_DIR)/libstratosphere/$(ATMOSPHERE_LIBRARY_DIR)/libstratosphere.a

%.npdm  :   %.npdm.json
	@echo built ... $< $@
	@npdmtool $< $@
	@echo built ... $(notdir $@)

#---------------------------------------------------------------------------------
# you need a rule like this for each extension you use as binary data
#---------------------------------------------------------------------------------
%.bin.o	:	%.bin
#---------------------------------------------------------------------------------
	@echo $(notdir $<)
	@$(bin2o)

-include $(DEPENDS)

#---------------------------------------------------------------------------------------
endif
#---------------------------------------------------------------------------------------

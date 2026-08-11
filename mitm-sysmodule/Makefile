#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

TOPDIR ?= $(CURDIR)
LOCAL_MK ?= $(TOPDIR)/local.mk
-include $(LOCAL_MK)
ATMOSPHERE_LIBS_DIR := $(abspath $(TOPDIR)/../common/lib/Atmosphere-libs)
ATMOSPHERE_LIBS_INCLUDE_DIR := ../common/lib/Atmosphere-libs
HOST_ONLY_GOALS := test test-sanitize format-check static-check tidy-check diff-check verify
HOST_ONLY_BUILD := $(strip $(filter $(HOST_ONLY_GOALS),$(MAKECMDGOALS)))

ifeq ($(HOST_ONLY_BUILD),)
ifeq ($(strip $(TOOLBOX_FORWARDER_PROGRAM_ID)),)
$(error Set TOOLBOX_FORWARDER_PROGRAM_ID in $(LOCAL_MK) or on the make command line)
endif

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>/devkitpro")
endif

include $(DEVKITPRO)/libnx/switch_rules
include $(ATMOSPHERE_LIBS_DIR)/config/templates/stratosphere.mk
endif

TARGET		:= wgnx-mitm
BUILD		:= build
OUTDIR		:= out
TITLE_ID	:= 010000000000EAD3
DISTDIR 	:= $(OUTDIR)/atmosphere/contents/$(TITLE_ID)
SOURCES 	:= src
INCLUDES 	:= \
				../common/include src \
				$(ATMOSPHERE_LIBS_INCLUDE_DIR)/libstratosphere/include \
				$(ATMOSPHERE_LIBS_INCLUDE_DIR)/libvapours/include
LIBNAMES	:= $(ATMOSPHERE_LIBS_DIR)/libstratosphere

#---------------------------------------------------------------------------------
# version control constants
#---------------------------------------------------------------------------------
APP_VERSION := 0.0.1-dev
WGNX_BUILD_ID := $(shell git -C $(TOPDIR)/.. describe --always --dirty 2>/dev/null || echo "unknown")

#---------------------------------------------------------------------------------
# host test framework config
#---------------------------------------------------------------------------------
HOST_CXX ?= g++
PYTHON ?= python3
CLANG_FORMAT ?= clang-format
CPPCHECK ?= cppcheck
CLANG_TIDY ?= clang-tidy-21
VERIFY_SOURCES := $(TOPDIR)/../tools/verify_sources.py
HOST_TEST_CXX_STANDARD ?= -std=c++2b
HOST_TEST_CXXFLAGS := $(HOST_TEST_CXX_STANDARD) -Wall -Wextra -Wpedantic -Werror
HOST_TEST_DIR := $(OUTDIR)/host-test
HOST_TEST_TARGET := $(HOST_TEST_DIR)/mitm-host-test
HOST_SANITIZE_DIR := $(OUTDIR)/host-test-sanitize
HOST_SANITIZE_TARGET := $(HOST_SANITIZE_DIR)/mitm-host-test
HOST_TEST_SOURCES	:= \
						test/policy_tests.cpp \
						test/bsd_socket_state_tests.cpp \
						test/bsd_tunneled_contract_tests.cpp \
						test/tunnel_discovery_tests.cpp \
						test/tunnel_completion_validation_tests.cpp \
						test/tunnel_datagram_receive_tests.cpp \
						test/tunnel_flow_readiness_tests.cpp \
						test/tunnel_flow_submission_state_tests.cpp
HOST_TEST_INCLUDES := -I$(CURDIR)/src -I$(CURDIR)/../common/include

#---------------------------------------------------------------------------------
# diagnostics
#---------------------------------------------------------------------------------
MITM_PACKET_DIAGNOSTICS ?= 0

#---------------------------------------------------------------------------------
# options for code generation
#---------------------------------------------------------------------------------
DEFINES += -DDISABLE_IPC -D__SWITCH__ \
	-DWGNX_MITM_TOOLBOX_FORWARDER_PROGRAM_ID=$(TOOLBOX_FORWARDER_PROGRAM_ID) \
	-DWGNX_MITM_PACKET_DIAGNOSTICS=$(MITM_PACKET_DIAGNOSTICS) \
	-DTARGET="\"$(TARGET)\"" \
	-DWGNX_VERSION="\"$(APP_VERSION)\"" \
	-DWGNX_BUILD_ID="\"$(WGNX_BUILD_ID)\""

CFLAGS += $(INCLUDE) -Wno-unused-result -fstack-usage
CXXFLAGS += $(CFLAGS) -std=c++23 -Werror=frame-larger-than=8192

#---------------------------------------------------------------------------------
# list of directories containing libraries, this must be the top level containing
# include and lib
#---------------------------------------------------------------------------------
LIBDIRS += $(LIBNAMES)

#---------------------------------------------------------------------------------
# no real need to edit anything past this point unless you need to add additional
# rules for different file extensions
#---------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#---------------------------------------------------------------------------------

export OUTPUT := $(CURDIR)/$(OUTDIR)/$(TARGET)
export TOPDIR := $(CURDIR)

export VPATH := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))

export DEPSDIR := $(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES	:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
BINFILES	:=	$(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.*)))

export OFILES	:= $(CPPFILES:.cpp=.o)
export LD 		:= $(CXX)

export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
	$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
	$(foreach dir,$(AMS_LIBDIRS),-I$(dir)/include) \
	-I$(CURDIR)/$(BUILD)

export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib) \
	$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/lib) \
	$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/$(ATMOSPHERE_LIBRARY_DIR))

export APP_JSON := $(TOPDIR)/res/module.json

.PHONY: $(BUILD) all clean clean-libs clean-build libs dist test test-sanitize format-check static-check tidy-check diff-check verify

all: $(BUILD) $(OUTDIR)/toolbox.json

$(OUTDIR)/toolbox.json: Makefile
	@mkdir -p $(OUTDIR)
	@printf '{\n  "name": "Tun-MITM",\n  "tid": "$(TITLE_ID)",\n  "requires_reboot": false,\n  "shutdown_service": "wgm:ctl",\n  "shutdown_cmd": 3\n}\n' > $@

dist: $(BUILD) $(OUTDIR)/toolbox.json
	@[ -d $(DISTDIR)/flags ] || mkdir -p $(DISTDIR)/flags
	@cp $(OUTDIR)/$(TARGET).nsp $(DISTDIR)/exefs.nsp
	@cp $(OUTDIR)/toolbox.json $(DISTDIR)/toolbox.json
	@: > $(DISTDIR)/flags/boot2.flag
	@echo "prepared Atmosphere layout in $(DISTDIR)"

test: $(HOST_TEST_TARGET)
	@$(HOST_TEST_TARGET)

test-sanitize: $(HOST_SANITIZE_TARGET)
	@ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 $(HOST_SANITIZE_TARGET)

format-check:
	@$(PYTHON) $(VERIFY_SOURCES) format --root $(TOPDIR) --config $(TOPDIR)/verify_sources.json --formatter $(CLANG_FORMAT)

static-check:
	@$(PYTHON) $(VERIFY_SOURCES) static --root $(TOPDIR) --config $(TOPDIR)/verify_sources.json --analyzer $(CPPCHECK)

tidy-check:
	@$(PYTHON) $(VERIFY_SOURCES) tidy --root $(TOPDIR) --config $(TOPDIR)/verify_sources.json --tidy $(CLANG_TIDY)

diff-check:
	@git -C $(TOPDIR)/.. diff --check
	@git -C $(TOPDIR)/.. diff --cached --check

verify:
	@$(MAKE) --no-print-directory format-check
	@$(MAKE) --no-print-directory static-check
	@$(MAKE) --no-print-directory tidy-check
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory test-sanitize
	@$(MAKE) --no-print-directory all
	@$(MAKE) --no-print-directory diff-check
	@echo "verification passed"

$(HOST_TEST_TARGET): Makefile $(HOST_TEST_SOURCES) src/bsd_endpoint.hpp src/bsd_response.hpp src/bsd_socket_state.hpp src/bsd_tunneled_contract.hpp src/build_config.hpp src/mitm_policy.hpp src/terminal_server_lifecycle.hpp src/tunnel_completion_validation.hpp src/tunnel_datagram_receive.hpp src/tunnel_discovery_state.hpp src/tunnel_flow_readiness.hpp src/tunnel_flow_result.hpp src/tunnel_flow_submission_state.hpp src/tunnel_open_disposition.hpp test/bsd_socket_state_tests.hpp test/bsd_tunneled_contract_tests.hpp test/tunnel_completion_validation_tests.hpp test/tunnel_datagram_receive_tests.hpp test/tunnel_discovery_tests.hpp test/tunnel_flow_readiness_tests.hpp test/tunnel_flow_submission_state_tests.hpp
	@[ -d $(HOST_TEST_DIR) ] || mkdir -p $(HOST_TEST_DIR)
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_SOURCES)) -o $(HOST_TEST_TARGET)

$(HOST_SANITIZE_TARGET): Makefile $(HOST_TEST_SOURCES) src/bsd_endpoint.hpp src/bsd_response.hpp src/bsd_socket_state.hpp src/bsd_tunneled_contract.hpp src/build_config.hpp src/mitm_policy.hpp src/terminal_server_lifecycle.hpp src/tunnel_completion_validation.hpp src/tunnel_datagram_receive.hpp src/tunnel_discovery_state.hpp src/tunnel_flow_readiness.hpp src/tunnel_flow_result.hpp src/tunnel_flow_submission_state.hpp src/tunnel_open_disposition.hpp test/bsd_socket_state_tests.hpp test/bsd_tunneled_contract_tests.hpp test/tunnel_completion_validation_tests.hpp test/tunnel_datagram_receive_tests.hpp test/tunnel_discovery_tests.hpp test/tunnel_flow_readiness_tests.hpp test/tunnel_flow_submission_state_tests.hpp
	@[ -d $(HOST_SANITIZE_DIR) ] || mkdir -p $(HOST_SANITIZE_DIR)
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_SOURCES)) -o $(HOST_SANITIZE_TARGET)

libs:
	@$(foreach lib,$(LIBNAMES),$(MAKE) --no-print-directory -C $(lib) && ) true

$(BUILD): libs
	@[ -d $@ ] || mkdir -p $@
	@[ -d $(OUTDIR) ] || mkdir -p $(OUTDIR)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean-libs:
	@$(foreach lib,$(LIBNAMES),$(MAKE) -C $(lib) clean && ) true

clean-build:
	@rm -rf $(BUILD) $(OUTDIR)

clean: clean-libs clean-build

else

.PHONY: force-build-info

DEPENDS := $(OFILES:.o=.d)

all: $(OUTPUT).nsp

$(OUTPUT).nsp: $(OUTPUT).nso $(OUTPUT).npdm
$(OUTPUT).nso: $(OUTPUT).elf
$(OUTPUT).elf: $(OFILES)

main.o: force-build-info

force-build-info:

$(OFILES): $(ATMOSPHERE_LIBRARIES_DIR)/libstratosphere/$(ATMOSPHERE_LIBRARY_DIR)/libstratosphere.a

%.npdm: %.npdm.json
	@npdmtool $< $@

-include $(DEPENDS)

endif

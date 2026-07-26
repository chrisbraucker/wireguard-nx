#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

TOPDIR ?= $(CURDIR)
ATMOSPHERE_LIBS_DIR := $(abspath $(TOPDIR)/../common/lib/Atmosphere-libs)
ATMOSPHERE_LIBS_INCLUDE_DIR := ../common/lib/Atmosphere-libs
HOST_ONLY_GOALS := test test-sanitize format-check diff-check
HOST_ONLY_BUILD := $(strip $(filter $(HOST_ONLY_GOALS),$(MAKECMDGOALS)))

ifeq ($(HOST_ONLY_BUILD),)
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

APP_VERSION := 0.0.1-dev
BUILD_ID := $(shell git -C $(TOPDIR)/.. describe --always --dirty 2>/dev/null || echo "unknown")
HOST_CXX ?= g++
PYTHON ?= python3
CLANG_FORMAT ?= clang-format
HOST_TEST_CXX_STANDARD ?= -std=c++2b
HOST_TEST_CXXFLAGS := $(HOST_TEST_CXX_STANDARD) -Wall -Wextra -Wpedantic -Werror
HOST_TEST_DIR := $(OUTDIR)/host-test
HOST_TEST_TARGET := $(HOST_TEST_DIR)/mitm-host-test
HOST_SANITIZE_DIR := $(OUTDIR)/host-test-sanitize
HOST_SANITIZE_TARGET := $(HOST_SANITIZE_DIR)/mitm-host-test
HOST_TEST_SOURCES := test/policy_tests.cpp
HOST_TEST_INCLUDES := -I$(CURDIR)/src

DEFINES += -DDISABLE_IPC -D__SWITCH__ \
	-DTARGET="\"$(TARGET)\"" \
	-DVERSION="\"$(APP_VERSION)\"" \
	-DBUILD_ID="\"$(BUILD_ID)\""

CFLAGS += $(INCLUDE) -Wno-unused-result -fstack-usage
CXXFLAGS += $(CFLAGS) -std=c++23 -Werror=frame-larger-than=8192
LIBDIRS += $(LIBNAMES)

ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT := $(CURDIR)/$(OUTDIR)/$(TARGET)
export TOPDIR := $(CURDIR)
export VPATH := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR := $(CURDIR)/$(BUILD)
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
export OFILES := $(CPPFILES:.cpp=.o)
export LD := $(CXX)
export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
	$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
	$(foreach dir,$(AMS_LIBDIRS),-I$(dir)/include) \
	-I$(CURDIR)/$(BUILD)
export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib) \
	$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/lib) \
	$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/$(ATMOSPHERE_LIBRARY_DIR))
export APP_JSON := $(TOPDIR)/res/module.json

.PHONY: $(BUILD) all clean clean-libs clean-build libs dist test test-sanitize format-check diff-check verify

all: $(BUILD)

dist: $(BUILD)
	@[ -d $(DISTDIR)/flags ] || mkdir -p $(DISTDIR)/flags
	@cp $(OUTDIR)/$(TARGET).nsp $(DISTDIR)/exefs.nsp
	@printf '{\n  "name": "WireGuard-NX MITM",\n  "tid": "$(TITLE_ID)",\n  "requires_reboot": false\n}\n' > $(DISTDIR)/toolbox.json
	@: > $(DISTDIR)/flags/boot2.flag
	@echo "prepared Atmosphere layout in $(DISTDIR)"

test: $(HOST_TEST_TARGET)
	@$(HOST_TEST_TARGET)

test-sanitize: $(HOST_SANITIZE_TARGET)
	@ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 $(HOST_SANITIZE_TARGET)

format-check:
	@$(PYTHON) $(TOPDIR)/../wg-sysmodule/tools/verify_sources.py format --root $(TOPDIR) --formatter $(CLANG_FORMAT)

diff-check:
	@git -C $(TOPDIR)/.. diff --check
	@git -C $(TOPDIR)/.. diff --cached --check

verify:
	@$(MAKE) --no-print-directory format-check
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory test-sanitize
	@$(MAKE) --no-print-directory all
	@$(MAKE) --no-print-directory diff-check
	@echo "verification passed"

$(HOST_TEST_TARGET): Makefile $(HOST_TEST_SOURCES) src/mitm_policy.hpp
	@[ -d $(HOST_TEST_DIR) ] || mkdir -p $(HOST_TEST_DIR)
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_SOURCES)) -o $(HOST_TEST_TARGET)

$(HOST_SANITIZE_TARGET): Makefile $(HOST_TEST_SOURCES) src/mitm_policy.hpp
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

DEPENDS := $(OFILES:.o=.d)

all: $(OUTPUT).nsp

$(OUTPUT).nsp: $(OUTPUT).nso $(OUTPUT).npdm
$(OUTPUT).nso: $(OUTPUT).elf
$(OUTPUT).elf: $(OFILES)

$(OFILES): $(ATMOSPHERE_LIBRARIES_DIR)/libstratosphere/$(ATMOSPHERE_LIBRARY_DIR)/libstratosphere.a

%.npdm: %.npdm.json
	@npdmtool $< $@

-include $(DEPENDS)

endif

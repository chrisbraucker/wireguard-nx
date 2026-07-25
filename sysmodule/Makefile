#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

TOPDIR ?= $(CURDIR)
HOST_ONLY_GOALS := test test-sanitize test-tsan test-warnings format-check static-check diff-check fuzz fuzz-run fuzz-seeds
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
SOURCES		+=	src src/runtime src/runtime/peer src/platform src/platform/horizon src/wireguard src/wireguard/crypto src/wireguard/crypto/third_party/blake2
INCLUDES	+=	../common/include \
			src \
			src/platform/horizon \
			$(TOPDIR)/lib/Atmosphere-libs/libstratosphere/include \
			$(TOPDIR)/lib/Atmosphere-libs/libvapours/include
LIBNAMES	:= Atmosphere-libs/libstratosphere

HOST_CXX	?= g++
HOST_CC		?= cc
PYTHON		?= python3
# Both GCC and Clang 16 accept the C++23 draft spelling, unlike Clang's newer c++23 alias.
HOST_TEST_CXX_STANDARD ?= -std=c++2b
HOST_TEST_CXXFLAGS := $(HOST_TEST_CXX_STANDARD) -Wall -Wextra -Wpedantic -Werror
HOST_TEST_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror
HOST_SANITIZE_CFLAGS := $(HOST_TEST_CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer
HOST_TSAN_CFLAGS := $(HOST_TEST_CFLAGS) -fsanitize=thread -fno-omit-frame-pointer
HOST_WARNING_CXXFLAGS := $(HOST_TEST_CXXFLAGS) -Wshadow -Wformat=2
HOST_TEST_DIR	:= $(OUTDIR)/host-test
HOST_TEST_TARGET := $(HOST_TEST_DIR)/wireguard-host-test
HOST_SANITIZE_DIR := $(OUTDIR)/host-test-sanitize
HOST_SANITIZE_TARGET := $(HOST_SANITIZE_DIR)/wireguard-host-test
HOST_TSAN_DIR := $(OUTDIR)/host-test-tsan
HOST_TSAN_TARGET := $(HOST_TSAN_DIR)/wireguard-host-test
HOST_WARNING_DIR := $(OUTDIR)/host-test-warnings
HOST_WARNING_TARGET := $(HOST_WARNING_DIR)/wireguard-host-test
FUZZ_CXX	?= clang++
FUZZ_DIR	:= $(OUTDIR)/fuzz
FUZZ_SECONDS	?= 30
FUZZ_COMMON_FLAGS := -std=c++2b -Wall -Wextra -Wpedantic -Werror -g -O1 \
	-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
FUZZ_CONFIG_ENDPOINT_TARGET := $(FUZZ_DIR)/config_endpoint_fuzz
FUZZ_MESSAGE_ADMISSION_TARGET := $(FUZZ_DIR)/message_admission_fuzz
FUZZ_INNER_IP_TARGET := $(FUZZ_DIR)/inner_ip_fuzz
FUZZ_RESOLVER_RESULT_TARGET := $(FUZZ_DIR)/resolver_result_fuzz
FUZZ_TARGETS := $(FUZZ_CONFIG_ENDPOINT_TARGET) $(FUZZ_MESSAGE_ADMISSION_TARGET) $(FUZZ_INNER_IP_TARGET) $(FUZZ_RESOLVER_RESULT_TARGET)
FUZZ_CORPUS_DIR := $(TOPDIR)/test/fuzz/corpus
FUZZ_GENERATED_CORPUS_DIR := $(FUZZ_DIR)/corpus
FUZZ_GENERATED_CONFIG_CORPUS_DIR := $(FUZZ_GENERATED_CORPUS_DIR)/config_endpoint
FUZZ_SEED_WRITER := $(FUZZ_DIR)/fuzz_seed_writer
CLANG_FORMAT ?= clang-format
CPPCHECK ?= cppcheck
VERIFY_SOURCES := $(TOPDIR)/tools/verify_sources.py
HOST_TEST_CPP_SOURCES := \
	src/runtime/debug_probe_runner.cpp \
	src/runtime/endpoint_resolver.cpp \
	src/runtime/packet_data_plane.cpp \
	src/runtime/peer/peer_runtime.cpp \
	src/runtime/peer/activation.cpp \
	src/runtime/peer/inbound.cpp \
	src/runtime/peer/lifecycle.cpp \
	src/runtime/peer/outbound.cpp \
	src/runtime/peer/peer_timers.cpp \
	src/runtime/runtime_coordinator.cpp \
	src/runtime/timer_schedule.cpp \
	src/runtime/udp_binding.cpp \
	src/config_text_validation.cpp \
	src/platform/endpoint_parser.cpp \
	src/platform/resolver_serialization.cpp \
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
	test/host/crypto_primitive_tests.cpp \
	test/host/legacy_self_tests.cpp \
	test/host/platform_tests.cpp \
	test/host/scripted_platform.cpp \
	test/host/packet_data_plane_tests.cpp \
	test/host/protocol_tests.cpp \
	test/host/runtime_lifecycle_tests.cpp \
	test/host/timer_tests.cpp \
	test/host/failure_composition_tests.cpp \
	test/host/main.cpp
HOST_TEST_C_SOURCES := \
	src/wireguard/crypto/monocypher.c \
	src/wireguard/crypto/third_party/blake2/blake2s-ref.c
HOST_TEST_C_OBJECT_NAMES := $(notdir $(HOST_TEST_C_SOURCES:.c=.o))
HOST_TEST_C_HEADERS := $(shell find $(TOPDIR)/src/wireguard/crypto -type f -name '*.h')
HOST_TEST_HEADERS := $(shell find $(TOPDIR)/test/host $(TOPDIR)/src $(TOPDIR)/../common/include -type f -name '*.hpp')
HOST_TEST_C_INCLUDES := \
	-I$(CURDIR)/src/wireguard/crypto \
	-I$(CURDIR)/src/wireguard/crypto/third_party/blake2
HOST_TEST_INCLUDES := \
	-I$(CURDIR)/test/host \
	-I$(CURDIR)/test/host/include \
	-I$(CURDIR)/../common/include \
	-I$(CURDIR)/src

define compile_host_c_sources
	@for source in $(HOST_TEST_C_SOURCES); do \
		object=$$(basename "$$source" .c).o; \
		$(HOST_CC) $(1) $(HOST_TEST_C_INCLUDES) -c $(CURDIR)/$$source -o $(2)/$$object || exit $$?; \
	done
endef
FUZZ_CONFIG_ENDPOINT_SOURCES := \
	src/config_text_validation.cpp \
	src/platform/endpoint_parser.cpp \
	test/fuzz/config_endpoint_fuzz.cpp
FUZZ_MESSAGE_ADMISSION_SOURCES := \
	src/wireguard/messages.cpp \
	src/wireguard/dispatch.cpp \
	test/fuzz/message_admission_fuzz.cpp
FUZZ_INNER_IP_SOURCES := \
	src/wireguard/inner_packet.cpp \
	test/fuzz/inner_ip_fuzz.cpp
FUZZ_RESOLVER_RESULT_SOURCES := \
	src/platform/resolver_serialization.cpp \
	test/fuzz/resolver_result_fuzz.cpp
FUZZ_HEADERS := $(shell find $(TOPDIR)/src $(TOPDIR)/../common/include -type f -name '*.hpp')

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

CFLAGS	+= $(INCLUDE) -Wno-unused-result -fstack-usage

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


.PHONY	: $(BUILD) clean clean-libs clean-build all libs dist test test-sanitize test-tsan \
		test-warnings format-check static-check diff-check verify prepare-build-id check-stack \
		report-footprint resource-report fuzz fuzz-run fuzz-seeds

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

test-tsan: $(HOST_TSAN_TARGET)
	@TSAN_OPTIONS=halt_on_error=1 $(HOST_TSAN_TARGET)

test-warnings: $(HOST_WARNING_TARGET)
	@$(HOST_WARNING_TARGET)

fuzz: $(FUZZ_TARGETS)

fuzz-run: fuzz fuzz-seeds
	@$(FUZZ_CONFIG_ENDPOINT_TARGET) $(FUZZ_GENERATED_CONFIG_CORPUS_DIR) $(FUZZ_CORPUS_DIR)/config_endpoint -max_total_time=$(FUZZ_SECONDS) -max_len=16384
	@$(FUZZ_MESSAGE_ADMISSION_TARGET) $(FUZZ_GENERATED_CORPUS_DIR)/message_admission -max_total_time=$(FUZZ_SECONDS) -max_len=66000
	@$(FUZZ_INNER_IP_TARGET) $(FUZZ_GENERATED_CORPUS_DIR)/inner_ip -max_total_time=$(FUZZ_SECONDS) -max_len=66000
	@$(FUZZ_RESOLVER_RESULT_TARGET) $(FUZZ_GENERATED_CORPUS_DIR)/resolver_result -max_total_time=$(FUZZ_SECONDS) -max_len=16384

fuzz-seeds: $(FUZZ_SEED_WRITER)
	@[ -d $(FUZZ_GENERATED_CORPUS_DIR) ] || mkdir -p $(FUZZ_GENERATED_CORPUS_DIR)
	@[ -d $(FUZZ_GENERATED_CONFIG_CORPUS_DIR) ] || mkdir -p $(FUZZ_GENERATED_CONFIG_CORPUS_DIR)
	@$(FUZZ_SEED_WRITER) $(FUZZ_GENERATED_CORPUS_DIR)

format-check:
	@$(PYTHON) $(VERIFY_SOURCES) format --root $(TOPDIR) --formatter $(CLANG_FORMAT)

static-check:
	@$(PYTHON) $(VERIFY_SOURCES) static --root $(TOPDIR) --analyzer $(CPPCHECK)

diff-check:
	@git -C $(TOPDIR) diff --check
	@git -C $(TOPDIR) diff --cached --check

verify:
	@$(MAKE) --no-print-directory format-check
	@$(MAKE) --no-print-directory static-check
	@$(MAKE) --no-print-directory test-warnings
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory test-sanitize
	@$(MAKE) --no-print-directory all
	@$(MAKE) --no-print-directory resource-report
	@$(MAKE) --no-print-directory diff-check
	@echo "verification passed"

check-stack: $(BUILD)
	@$(PYTHON) $(TOPDIR)/../tools/check_stack_usage.py

report-footprint: $(BUILD)
	@$(PYTHON) $(TOPDIR)/../tools/report_footprint.py

resource-report: check-stack report-footprint

$(HOST_TEST_TARGET): Makefile $(HOST_TEST_CPP_SOURCES) $(HOST_TEST_C_SOURCES) $(HOST_TEST_C_HEADERS) $(HOST_TEST_HEADERS)
	@[ -d $(HOST_TEST_DIR) ] || mkdir -p $(HOST_TEST_DIR)
	$(call compile_host_c_sources,$(HOST_TEST_CFLAGS),$(HOST_TEST_DIR))
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_CPP_SOURCES)) $(addprefix $(HOST_TEST_DIR)/,$(HOST_TEST_C_OBJECT_NAMES)) -o $(HOST_TEST_TARGET)

$(FUZZ_SEED_WRITER): Makefile test/fuzz/fuzz_seed_writer.cpp test/fuzz/fuzz_seed_data.hpp
	@[ -d $(FUZZ_DIR) ] || mkdir -p $(FUZZ_DIR)
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) -I$(CURDIR)/test/fuzz $(CURDIR)/test/fuzz/fuzz_seed_writer.cpp -o $(FUZZ_SEED_WRITER)

$(HOST_SANITIZE_TARGET): Makefile $(HOST_TEST_CPP_SOURCES) $(HOST_TEST_C_SOURCES) $(HOST_TEST_C_HEADERS) $(HOST_TEST_HEADERS)
	@[ -d $(HOST_SANITIZE_DIR) ] || mkdir -p $(HOST_SANITIZE_DIR)
	$(call compile_host_c_sources,$(HOST_SANITIZE_CFLAGS),$(HOST_SANITIZE_DIR))
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_CPP_SOURCES)) $(addprefix $(HOST_SANITIZE_DIR)/,$(HOST_TEST_C_OBJECT_NAMES)) -o $(HOST_SANITIZE_TARGET)

$(HOST_TSAN_TARGET): Makefile $(HOST_TEST_CPP_SOURCES) $(HOST_TEST_C_SOURCES) $(HOST_TEST_C_HEADERS) $(HOST_TEST_HEADERS)
	@[ -d $(HOST_TSAN_DIR) ] || mkdir -p $(HOST_TSAN_DIR)
	$(call compile_host_c_sources,$(HOST_TSAN_CFLAGS),$(HOST_TSAN_DIR))
	@$(HOST_CXX) $(HOST_TEST_CXXFLAGS) -fsanitize=thread -fno-omit-frame-pointer $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_CPP_SOURCES)) $(addprefix $(HOST_TSAN_DIR)/,$(HOST_TEST_C_OBJECT_NAMES)) -o $(HOST_TSAN_TARGET)

$(HOST_WARNING_TARGET): Makefile $(HOST_TEST_CPP_SOURCES) $(HOST_TEST_C_SOURCES) $(HOST_TEST_C_HEADERS) $(HOST_TEST_HEADERS)
	@[ -d $(HOST_WARNING_DIR) ] || mkdir -p $(HOST_WARNING_DIR)
	$(call compile_host_c_sources,$(HOST_TEST_CFLAGS),$(HOST_WARNING_DIR))
	@$(HOST_CXX) $(HOST_WARNING_CXXFLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(HOST_TEST_CPP_SOURCES)) $(addprefix $(HOST_WARNING_DIR)/,$(HOST_TEST_C_OBJECT_NAMES)) -o $(HOST_WARNING_TARGET)

$(FUZZ_CONFIG_ENDPOINT_TARGET): Makefile $(FUZZ_CONFIG_ENDPOINT_SOURCES) $(FUZZ_HEADERS)
	@[ -d $(FUZZ_DIR) ] || mkdir -p $(FUZZ_DIR)
	@command -v $(FUZZ_CXX) >/dev/null || { echo "missing FUZZ_CXX=$(FUZZ_CXX); install Clang with libFuzzer support or set FUZZ_CXX" >&2; exit 1; }
	@$(FUZZ_CXX) $(FUZZ_COMMON_FLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(FUZZ_CONFIG_ENDPOINT_SOURCES)) -o $(FUZZ_CONFIG_ENDPOINT_TARGET)

$(FUZZ_MESSAGE_ADMISSION_TARGET): Makefile $(FUZZ_MESSAGE_ADMISSION_SOURCES) $(FUZZ_HEADERS)
	@[ -d $(FUZZ_DIR) ] || mkdir -p $(FUZZ_DIR)
	@command -v $(FUZZ_CXX) >/dev/null || { echo "missing FUZZ_CXX=$(FUZZ_CXX); install Clang with libFuzzer support or set FUZZ_CXX" >&2; exit 1; }
	@$(FUZZ_CXX) $(FUZZ_COMMON_FLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(FUZZ_MESSAGE_ADMISSION_SOURCES)) -o $(FUZZ_MESSAGE_ADMISSION_TARGET)

$(FUZZ_INNER_IP_TARGET): Makefile $(FUZZ_INNER_IP_SOURCES) $(FUZZ_HEADERS)
	@[ -d $(FUZZ_DIR) ] || mkdir -p $(FUZZ_DIR)
	@command -v $(FUZZ_CXX) >/dev/null || { echo "missing FUZZ_CXX=$(FUZZ_CXX); install Clang with libFuzzer support or set FUZZ_CXX" >&2; exit 1; }
	@$(FUZZ_CXX) $(FUZZ_COMMON_FLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(FUZZ_INNER_IP_SOURCES)) -o $(FUZZ_INNER_IP_TARGET)

$(FUZZ_RESOLVER_RESULT_TARGET): Makefile $(FUZZ_RESOLVER_RESULT_SOURCES) $(FUZZ_HEADERS)
	@[ -d $(FUZZ_DIR) ] || mkdir -p $(FUZZ_DIR)
	@command -v $(FUZZ_CXX) >/dev/null || { echo "missing FUZZ_CXX=$(FUZZ_CXX); install Clang with libFuzzer support or set FUZZ_CXX" >&2; exit 1; }
	@$(FUZZ_CXX) $(FUZZ_COMMON_FLAGS) $(HOST_TEST_INCLUDES) $(addprefix $(CURDIR)/,$(FUZZ_RESOLVER_RESULT_SOURCES)) -o $(FUZZ_RESOLVER_RESULT_TARGET)

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

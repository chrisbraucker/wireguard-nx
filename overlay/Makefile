#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

HOST_ONLY_GOALS := format-check static-check tidy-check diff-check verify
HOST_ONLY_BUILD := $(strip $(filter $(HOST_ONLY_GOALS),$(MAKECMDGOALS)))

TOPDIR ?= $(CURDIR)
ifeq ($(HOST_ONLY_BUILD),)
ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>/devkitpro")
endif

include $(DEVKITPRO)/libnx/switch_rules
include ${TOPDIR}/lib/libultrahand/ultrahand.mk
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
RESOURCES	:=	res
SOURCES		+=	src
DATA		:=	data
INCLUDES	+=	../common/include

APP_TITLE	:=	WireGuard-NX
NO_ICON		:=	1

#---------------------------------------------------------------------------------
# version control constants
#---------------------------------------------------------------------------------
APP_VERSION		:= 0.0.1-dev
WGNX_BUILD_ID		:= $(shell git describe --always --dirty 2>/dev/null || echo "unknown")

PYTHON ?= python3
CLANG_FORMAT ?= clang-format
CPPCHECK ?= cppcheck
CLANG_TIDY ?= clang-tidy-21
VERIFY_SOURCES := $(TOPDIR)/../tools/verify_sources.py

#---------------------------------------------------------------------------------
# options for code generation
#---------------------------------------------------------------------------------
DEFINES	:=	-DDISABLE_IPC \
	-DTARGET="\"$(TARGET)\"" \
	-DAPP_TITLE="\"$(APP_TITLE)"\" \
	-DWGNX_VERSION="\"$(APP_VERSION)\"" \
	-DWGNX_BUILD_ID="\"$(WGNX_BUILD_ID)\""

ARCH	:=	-march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC

CFLAGS	:=	-g -Wall -Werror -O2 -ffunction-sections \
			$(ARCH) $(DEFINES)

CFLAGS	+=	$(INCLUDE) -D__SWITCH__

CXXFLAGS	:= $(CFLAGS) -fno-exceptions -std=gnu++26

ASFLAGS	:=	-g $(ARCH)
LDFLAGS	=	-specs=$(DEVKITPRO)/libnx/switch.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map)

LIBS	:= -lnx

#---------------------------------------------------------------------------------
# list of directories containing libraries, this must be the top level containing
# include and lib
#---------------------------------------------------------------------------------
LIBDIRS	:= $(PORTLIBS) $(LIBNX)

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

export OFILES	:=	$(addsuffix .o,$(BINFILES)) \
			$(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			-I$(CURDIR)/$(BUILD)

export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib)

export BUILD_EXEFS_SRC := $(TOPDIR)/$(EXEFS_SRC)

.PHONY: $(BUILD) clean all format-check static-check tidy-check diff-check verify

#---------------------------------------------------------------------------------
all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@[ -d $(OUTDIR) ] || mkdir -p $(OUTDIR)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

#---------------------------------------------------------------------------------
clean:
	@echo clean ...
	@rm -fr $(BUILD) $(TARGET).ovl $(TARGET).nacp $(TARGET).nso $(TARGET).elf $(OUTDIR)

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
	@$(MAKE) --no-print-directory diff-check
	@echo "verification passed"


#---------------------------------------------------------------------------------
else
.PHONY:	all force-build-info

DEPENDS		:= $(OFILES:.o=.d)

#---------------------------------------------------------------------------------
# main targets
#---------------------------------------------------------------------------------

all: $(OUTPUT).ovl

$(OUTPUT).ovl: $(OUTPUT).elf $(OUTPUT).nacp
	@elf2nro $< $@ --nacp=$(OUTPUT).nacp
	@echo "built ... $(notdir $(OUTPUT).ovl)"

$(OUTPUT).elf: $(OFILES)

GuiMain.o: force-build-info

force-build-info:

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

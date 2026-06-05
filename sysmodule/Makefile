#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>/devkitpro")
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITPRO)/libnx/switch_rules
include $(TOPDIR)/lib/Atmosphere-libs/config/templates/stratosphere.mk

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
SOURCES		+=	src src/platform/horizon
INCLUDES	+=	../common/include \
			src \
			src/platform/horizon \
			$(TOPDIR)/lib/Atmosphere-libs/libstratosphere/include \
			$(TOPDIR)/lib/Atmosphere-libs/libvapours/include
LIBNAMES	:= Atmosphere-libs/libstratosphere

#---------------------------------------------------------------------------------
# version control constants
#---------------------------------------------------------------------------------
APP_VERSION		:= 0.0.1-dev
BUILD_ID		:= $(shell git describe --always --dirty 2>/dev/null || echo "unknown")

#---------------------------------------------------------------------------------
# options for code generation
#---------------------------------------------------------------------------------
DEFINES	+=	-DDISABLE_IPC -D__SWITCH__ \
	-DTARGET="\"$(TARGET)\"" \
	-DVERSION="\"$(APP_VERSION)\"" \
	-DBUILD_ID="\"$(BUILD_ID)\""

CFLAGS	+= $(INCLUDE) -Wno-unused-result

CXXFLAGS	+= $(CFLAGS)

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

.PHONY	: $(BUILD) clean clean-libs clean-build all libs dist

#---------------------------------------------------------------------------------
all	: $(BUILD)

dist	: $(BUILD)
	@[ -d $(DISTDIR)/flags ] || mkdir -p $(DISTDIR)/flags
	@cp $(OUTDIR)/$(TARGET).nsp $(DISTDIR)/exefs.nsp
	@printf '{\n  "name": "WireGuard-NX",\n  "tid": "$(TITLE_ID)",\n  "requires_reboot": false\n}\n' > $(DISTDIR)/toolbox.json
	@: > $(DISTDIR)/flags/boot2.flag
	@echo "prepared Atmosphere layout in $(DISTDIR)"

libs	:
	@$(foreach lib,$(LIBNAMES),$(MAKE) --no-print-directory -C $(TOPDIR)/lib/$(lib) && ) true

$(LIBNAMES)	:
	@echo $@

$(BUILD)	: libs
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

#---------------------------------------------------------------------------------
# sys-slp-client Sysmodule Makefile
# Based on the Atmosphere stratosphere sysmodule template.
#---------------------------------------------------------------------------------

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../../Atmosphere-libs/config/templates/stratosphere.mk

#---------------------------------------------------------------------------------
TARGET		:=	sys-slp-client
BUILD		:=	build
SOURCES		:=	source source/slp source/slpcfg source/ldn source/bsd source/tunnel source/nifm
DATA		:=	data
INCLUDES	:=	source

TARGET_VERSION := 0.1.0

# Unique per build. Printed as the FIRST line of slp-trace.log so a trace can
# always be tied to an exact binary -- no more "is the console running the build
# I think I deployed?". Compare against `make print-build-id` / deploy output.
SLP_BUILD_ID := $(shell date +%Y%m%d-%H%M%S)

# Write the id into a header that is regenerated on EVERY make. A -D flag alone
# was not enough: main.o is only recompiled when main.cpp changes, so editing
# any OTHER file produced a new binary carrying a STALE build id -- precisely
# the "is this the build I deployed?" confusion the id exists to prevent.
# Touching this header every build forces main.cpp to rebuild, so the stamp
# always matches the binary.
BUILD_ID_HDR := $(shell printf '\043pragma once\n\043define SLP_BUILD_ID_STR "$(SLP_BUILD_ID)"\n' > source/build_id.h && echo ok)

CFLAGS		+= -DSLP_VERSION="\"${TARGET_VERSION}\"" -DSLP_BUILD_ID="\"${SLP_BUILD_ID}\""
CXXFLAGS	+= -DSLP_VERSION="\"${TARGET_VERSION}\"" -DSLP_BUILD_ID="\"${SLP_BUILD_ID}\""

# Debug trace to sdmc:/slp-trace.log (boot2-safe, ams::fs). Disable for release.
CFLAGS		+= -DSLPCFG_DEBUG_TRACE
CXXFLAGS	+= -DSLPCFG_DEBUG_TRACE

# libnx headers like <crypto/aes.h> live under include/switch/, not include/ directly.
CFLAGS		+= -I$(LIBNX)/include/switch
CXXFLAGS	+= -I$(LIBNX)/include/switch

# NOTE (2026-08-16): a `-Wno-error=maybe-uninitialized` hack used to live here.
# It was masking a stale Atmosphere-libs checkout, NOT a real code problem:
# the top-level Atmosphere-libs clone had been pinned to 82f1553 (AMS 1.11.1,
# max HOS 22.1.0, predating upstream's GCC 16 support), so on this GCC 16.1
# toolchain its own -Werror tripped at link time, and any binary that did link
# then aborted at boot with 0xFFE because the console runs HOS 22.5.0.
# Moving Atmosphere-libs to stock upstream master (1.11.2 / HOS 22.5.0, which
# includes "ams: basic support for compiling with gcc 16") fixes both, so the
# hack is gone. If it ever comes back, check the libs version FIRST -- do not
# silence the warning again.

#---------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#---------------------------------------------------------------------------------

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)

export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
			$(foreach dir,$(DATA),$(CURDIR)/$(dir))

export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES      :=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES    :=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES      :=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
BINFILES	:=	$(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.*)))

ifeq ($(strip $(CPPFILES)),)
	export LD	:=	$(CC)
else
	export LD	:=	$(CXX)
endif

export OFILES	:=	$(addsuffix .o,$(BINFILES)) \
			$(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			$(foreach dir,$(AMS_LIBDIRS),-I$(dir)/include) \
			-I$(CURDIR)/$(BUILD)

export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib) \
			$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/lib) \
			$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/$(ATMOSPHERE_LIBRARY_DIR))

export BUILD_EXEFS_SRC := $(TOPDIR)/$(EXEFS_SRC)
export APP_JSON := $(TOPDIR)/res/app.json

TITLE_ID	:=	4200000000000011

.PHONY: $(BUILD) clean all rebuild

all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

rebuild: clean all

clean:
	@echo clean ...
	@rm -fr $(BUILD) $(TARGET).kip $(TARGET).elf $(TARGET).nso $(TARGET).npdm $(TARGET).nsp

#---------------------------------------------------------------------------------
else
#---------------------------------------------------------------------------------
.PHONY: all

DEPENDS	:=	$(OFILES:.o=.d)

all: $(OUTPUT).nsp

$(OUTPUT).kip :	$(OUTPUT).elf
$(OUTPUT).nsp :	$(OUTPUT).nso $(OUTPUT).npdm
$(OUTPUT).nso :	$(OUTPUT).elf

$(OUTPUT).elf :	$(OFILES)

$(OFILES) : $(ATMOSPHERE_LIBRARIES_DIR)/libstratosphere/$(ATMOSPHERE_LIBRARY_DIR)/libstratosphere.a

%.npdm : $(APP_JSON)
	@echo built ... $< $@
	@npdmtool $< $@
	@echo built ... $(notdir $@)

-include $(DEPENDS)

#---------------------------------------------------------------------------------------
endif
#---------------------------------------------------------------------------------------

.PHONY: print-build-id
print-build-id:
	@echo $(SLP_BUILD_ID)

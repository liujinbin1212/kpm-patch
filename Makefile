# Makefile for Kernel Patch Module (KPM) build system
# Based on Beransnow/KPM-Build-Anywhere (originally by bmax121/KernelPatch)
#
# Targets: hello.kpm (pipeline demo) | kpm-hide.kpm (hiding module)
#          | hosts_file_redirect.kpm (hosts redirect)

ifeq ($(OS), Windows_NT)
    PLATFORM := windows-x86_64
else
    PLATFORM := linux-x86_64
endif

ifndef TARGET_COMPILE
	NDK_PATH := $(shell echo $(NDK_PATH))
 	export TARGET_COMPILE=$(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/
endif

# KernelPatch source (SukiSU fork). Override with: make KP_DIR=/path/to/KernelPatch
ifeq ($(strip $(KP_DIR)),)
    KP_DIR = $(CURDIR)/KernelPatch
endif

CC = $(TARGET_COMPILE)aarch64-linux-android31-clang
LD = $(TARGET_COMPILE)ld.lld
AS = $(TARGET_COMPILE)llvm-as
OBJCOPY = $(TARGET_COMPILE)llvm-objcopy
STRIP := $(TARGET_COMPILE)llvm-strip

INCLUDE_DIRS := include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := -I. -Iinclude $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS = -I$(AP_INCLUDE_PATH) $(INCLUDE_FLAGS) -Wall -Ofast -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden

LDFLAGS  += -s

all: hello.kpm kpm-hide.kpm hosts_file_redirect.kpm

# link (relocatable) + strip
hello.kpm: hello.o
	${CC} $(LDFLAGS) -r -o $@ $^
	${STRIP} -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@

kpm-hide.kpm: kpm-hide.o
	${CC} $(LDFLAGS) -r -o $@ $^
	${STRIP} -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@

hosts_file_redirect.kpm: hosts_file_redirect.o
	${CC} $(LDFLAGS) -r -o $@ $^
	${STRIP} -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@

# compile
hello.o: hello.c hello.lds
	${CC} $(CFLAGS) -Thello.lds -c -O2 -o $@ $<

kpm-hide.o: kpm-hide.c
	${CC} $(CFLAGS) -c -O2 -o $@ $<

hosts_file_redirect.o: hosts_file_redirect.c include/kpm_hook_utils.h
	${CC} $(CFLAGS) -c -O2 -o $@ $<

.PHONY: clean
ifeq ($(OS), Windows_NT)
clean:
	del /Q *.o *.kpm
else
clean:
	rm -rf *.o *.kpm
endif

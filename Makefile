SHELL := /bin/sh
.DEFAULT_GOAL := build

PROCESS_ARCH := $(shell /usr/bin/uname -m)
TRANSLATED := $(shell /usr/sbin/sysctl -in sysctl.proc_translated)
ifeq ($(PROCESS_ARCH),arm64)
NATIVE_ARCH := arm64
else ifeq ($(PROCESS_ARCH),x86_64)
ifeq ($(TRANSLATED),1)
NATIVE_ARCH := arm64
else ifeq ($(filter-out 0,$(TRANSLATED)),)
NATIVE_ARCH := x86_64
else
$(error Unexpected Rosetta translation state)
endif
else
$(error Cannot determine the physical Mac architecture)
endif

ARCH ?= $(NATIVE_ARCH)
ifeq ($(filter $(ARCH),arm64 x86_64),)
$(error ARCH must be arm64 or x86_64)
endif

BUILD_ROOT ?= build
OUT := $(BUILD_ROOT)/$(ARCH)
TEAM_ID ?=
VERSION ?=
KEYCHAIN ?=
APPLICATION_IDENTITY ?=
INSTALLER_IDENTITY ?=
MANIFEST ?=
PYTHON ?= python3
CLANG := xcrun clang
DEPLOYMENT := -arch $(ARCH) -mmacosx-version-min=15.0
WARNINGS := -Wall -Wextra -Werror
COMMON_FLAGS := $(DEPLOYMENT) $(WARNINGS) -O2 -fstack-protector-strong -Isrc
TEAM_DEFINE := -DWATCHID_TEAM_ID='"$(TEAM_ID)"'
SYSTEM_FRAMEWORKS := -framework CoreFoundation -framework Security \
	-framework SystemConfiguration -framework CoreGraphics
RELEASE_OPTIONS = --team-id "$(TEAM_ID)" --keychain "$(KEYCHAIN)" \
	--application-identity "$(APPLICATION_IDENTITY)" \
	--installer-identity "$(INSTALLER_IDENTITY)"

.PHONY: build build-all build-arm64 build-x86_64 check check-native \
	check-scripts check-artifacts notary-profile release cask

# Rebuild both binaries together so signing-team changes cannot reuse old objects.
build:
	@mkdir -p "$(OUT)"
	$(CLANG) $(COMMON_FLAGS) $(TEAM_DEFINE) -std=c11 -dynamiclib \
		src/pam_watchid.c src/watchid_common.c -lpam $(SYSTEM_FRAMEWORKS) \
		-Wl,-install_name,/Library/Security/pam_watchid/pam_watchid.so \
		-Wl,-exported_symbol,_pam_sm_authenticate \
		-Wl,-exported_symbol,_pam_sm_setcred \
		-o "$(OUT)/pam_watchid.so"
	$(CLANG) $(COMMON_FLAGS) $(TEAM_DEFINE) -std=gnu11 -fobjc-arc -fblocks \
		src/pam_watchid_helper.m src/watchid_common.c $(SYSTEM_FRAMEWORKS) \
		-framework Foundation -framework LocalAuthentication \
		-o "$(OUT)/pam_watchid-helper"

build-all: build-arm64 build-x86_64

build-arm64:
	$(MAKE) build ARCH=arm64

build-x86_64:
	$(MAKE) build ARCH=x86_64

check: build-all check-native check-scripts
	$(MAKE) check-artifacts

check-native:
	@mkdir -p "$(BUILD_ROOT)/tests"
	$(CLANG) -arch $(NATIVE_ARCH) -mmacosx-version-min=15.0 $(WARNINGS) \
		-std=c11 -Isrc tests/test_watchid.c src/watchid_common.c \
		$(SYSTEM_FRAMEWORKS) -o "$(BUILD_ROOT)/tests/test_watchid"
	"$(BUILD_ROOT)/tests/test_watchid"

check-scripts:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'
	/bin/sh -n packaging/uninstall.sh

check-artifacts:
	/bin/sh tests/check-artifacts.sh "$(BUILD_ROOT)"

notary-profile:
	$(PYTHON) scripts/release.py notary-profile $(RELEASE_OPTIONS)

release:
	$(PYTHON) scripts/release.py release --version "$(VERSION)" $(RELEASE_OPTIONS)

cask:
	$(PYTHON) scripts/generate_cask.py --manifest "$(MANIFEST)" \
		--output "$(BUILD_ROOT)/pam-watchid.rb"

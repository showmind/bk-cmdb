SHELL=bash
PWD=$(shell pwd)

space:=$()
comma:=,

ARCH?=$(shell uname -m)

# Version  : v3.2.2
# Tag          : release-v3.2.2
# BuildTime: 2019-02-19T16:48:43+0800
# GitHash  : 3185b32956a6e59df1ee0744c6edf72e09828778
# RunMode  : product

BUILDTIME?=$(shell date +%Y-%m-%dT%T%z)
GITHASH?=$(shell git rev-parse HEAD)
GITTAG?=$(shell git describe --all --tags --exact-match 2>/dev/null | awk -F '/' '{print $$NF}')
VERSION?=$(shell git symbolic-ref -q --short HEAD || git describe --all --tags --exact-match 2>/dev/null | awk -F '/' '{print $$NF}'|awk -F '-' '{print $$NF}')
ISDEBUG?=false
ISCI?=false
CCDistro?=community
GOVERSION?=$(shell go version | awk '{print $$3F}')
ifeq ($(ISDEBUG),true)
	GOBUILD_FLAGS = -ldflags "-X configcenter/src/common/version.CCRunMode=dev -X\
	configcenter/src/common/version.CCVersion=${VERSION} -X configcenter/src/common/version.CCBuildTime=${BUILDTIME} -X\
	configcenter/src/common/version.CCGitHash=${GITHASH} -X configcenter/src/common/version.CCTag=${GITTAG} -X\
	configcenter/src/common/version.CCDistro=${CCDistro} -X configcenter/src/common/version.GoVersion=${GOVERSION}"
else ifeq ($(ISCI),true)
	GOBUILD_FLAGS = -ldflags "-X configcenter/src/common/version.CCRunMode=for_ci -X\
	configcenter/src/common/version.CCVersion=${VERSION} -X configcenter/src/common/version.CCBuildTime=${BUILDTIME} -X\
	configcenter/src/common/version.CCGitHash=${GITHASH} -X configcenter/src/common/version.CCTag=${GITTAG} -X\
	configcenter/src/common/version.CCDistro=${CCDistro} -X configcenter/src/common/version.GoVersion=${GOVERSION}"
else
	GOBUILD_FLAGS = -ldflags "-X configcenter/src/common/version.CCVersion=${VERSION} -X\
	configcenter/src/common/version.CCBuildTime=${BUILDTIME} -X configcenter/src/common/version.CCGitHash=${GITHASH} -X\
	configcenter/src/common/version.CCTag=${GITTAG} -X configcenter/src/common/version.CCDistro=${CCDistro} -X\
	configcenter/src/common/version.GoVersion=${GOVERSION}"
endif

DOCS_DIR?=$(PROJECT_PATH)/docs
SCRIPT_DIR?=$(PROJECT_PATH)/scripts
RESOURCE_DIR?=$(PROJECT_PATH)/resources
SOURCE_ROOT?=$(PROJECT_PATH)/src
BUILD_DIR?=$(SOURCE_ROOT)/bin/build/$(VERSION)
BIN_PATH?=$(BUILD_DIR)
export OUTPUT_DIR = ${BIN_PATH}

GOFILES = $(shell find . -type f -name '*.go')
GOFILES_NOVENDOR = $(shell find . -type f -name '*.go' -not -path "*/vendor/*")
GOFILES_ALL = $(GOFILES)
NOW=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# crypto related environment variables
DISABLE_CRYPTO?=false
TONGSUO_PATH?=$(BUILD_DIR)/tongsuo
IS_STATIC?=false
ifeq ($(DISABLE_CRYPTO),true)
	GOBUILD_FLAGS:= -tags=disable_crypto $(GOBUILD_FLAGS)
else
	ifeq ($(IS_STATIC),true)
		CGO_BUILD_FLAGS= CGO_ENABLED=1 CGO_CFLAGS="-I${TONGSUO_PATH}/include -Wno-deprecated-declarations" \
		CGO_LDFLAGS="-L${TONGSUO_PATH}/lib -lssl -lcrypto -ldl -lpthread -static-libgcc -static-libstdc++"
	else
		CGO_BUILD_FLAGS= CGO_ENABLED=1 CGO_CFLAGS="-I${TONGSUO_PATH}/include -Wno-deprecated-declarations" \
		CGO_LDFLAGS="-L${TONGSUO_PATH}/lib -lssl -lcrypto"
	endif
endif

# available
TARGET_NAME?=
TARGET_PORT?=9999

PREPARE_CFG?=true

# building
${TARGET_NAME}: $(GOFILES_ALL)
ifeq ($(PREPARE_CFG),true)
	@python $(SCRIPT_DIR)/prepare_cfg.py $(BIN_PATH) $(TARGET_NAME) $(RESOURCE_DIR) $(SCRIPT_DIR) $(TARGET_PORT) $(VERSION)
	@echo
endif
	@echo -e "\033[34mbuilding the target: $@... \033[0m"
	@echo 
	$(CGO_BUILD_FLAGS) go build $(GOBUILD_FLAGS) -o $(BIN_PATH)/$(TARGET_NAME)/$(TARGET_NAME)
	@chmod +x  $(BIN_PATH)/$(TARGET_NAME)/$(TARGET_NAME)

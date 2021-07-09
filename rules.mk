# Only use the recipes defined in these makefiles
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:
# Delete target files if there's an error
# This avoids a failure to then skip building on next run if the output is created by shell redirection for example
# Not really necessary for now, but just good to have already if it becomes necessary later.
.DELETE_ON_ERROR:
# Treat the whole recipe as a one shell script/invocation instead of one-per-line
.ONESHELL:
# Use bash instead of plain sh
SHELL := bash
.SHELLFLAGS := -o pipefail -euc

.PHONY: all boots crosscompile dc image gen run test

CGO_ENABLED := 0
export CGO_ENABLED

GitRev := $(shell git rev-parse --short HEAD)
SOURCE_DATE_EPOCH := $(shell git log -1 --pretty=%ct)
export SOURCE_DATE_EPOCH

crossbinaries := cmd/boots/boots-linux-386 cmd/boots/boots-linux-amd64 cmd/boots/boots-linux-arm64 cmd/boots/boots-linux-armv6 cmd/boots/boots-linux-armv7
cmd/boots/boots-linux-386:   FLAGS=GOARCH=386
cmd/boots/boots-linux-amd64: FLAGS=GOARCH=amd64
cmd/boots/boots-linux-arm64: FLAGS=GOARCH=arm64
cmd/boots/boots-linux-armv6: FLAGS=GOARCH=arm GOARM=6
cmd/boots/boots-linux-armv7: FLAGS=GOARCH=arm GOARM=7
cmd/boots/boots-linux-386 cmd/boots/boots-linux-amd64 cmd/boots/boots-linux-arm64 cmd/boots/boots-linux-armv6 cmd/boots/boots-linux-armv7: boots
	${FLAGS} GOOS=linux go build -v -ldflags="-X main.GitRev=${GitRev}" -o $@ ./cmd/boots/

ifeq ($(origin GOBIN), undefined)
GOBIN := ${PWD}/bin
export GOBIN
PATH := ${GOBIN}:${PATH}
export PATH
endif

toolsBins := $(addprefix bin/,$(shell sed -n '/^\s*_/ s|.*/\(.*\)"|\1|p' tools.go | tr '\n' ' '))
tools: $(toolsBins)

$(toolsBins): tools.go
	go install $$(sed -n -e 's|^\s*_\s*"\(.*\)"$$|\1| p' tools.go | grep '$(@F)')
	
generated_files := \
	packet/mock_cacher/cacher_mock.go \
	packet/mock_workflow/workflow_mock.go \
	syslog/facility_string.go \
	syslog/severity_string.go \
	
.PHONY: $(generated_files)

# build all the ipxe binaries
build_all_ipxe: tftp/ipxe/ipxe.efi tftp/ipxe/snp-hua.efi tftp/ipxe/snp-nolacp.efi tftp/ipxe/undionly.kpxe tftp/ipxe/snp-hua.efi

# go generate
go_generate:
$(filter %_string.go,$(generated_files)): bin/stringer
$(filter %_mock.go,$(generated_files)): bin/mockgen
$(generated_files): bin/goimports
	go generate -run="$(@F)" ./...
	goimports -w $@

# this is quick and its really only for rebuilding when dev'ing, I wish go would
# output deps in make syntax like gcc does... oh well this is good enough
cmd/boots/boots: $(shell git ls-files | grep -v -e vendor -e '_test.go' | grep '.go$$' ) build_all_ipxe go_generate syslog/facility_string.go syslog/severity_string.go
	go build -v -ldflags="-X main.GitRev=${GitRev}" -o $@ ./cmd/boots/

include ipxev.mk
ipxeconfigs := $(wildcard ipxe/ipxe/*.h)

# copy ipxe binaries into location available for go embed
tftp/ipxe/ipxe.efi: ipxe/ipxe/build/bin-x86_64-efi/ipxe.efi
tftp/ipxe/snp-nolacp.efi: ipxe/ipxe/build/bin-arm64-efi/snp.efi
tftp/ipxe/undionly.kpxe: ipxe/ipxe/build/bin/undionly.kpxe
tftp/ipxe/ipxe.efi tftp/ipxe/snp-nolacp.efi tftp/ipxe/undionly.kpxe:
	mkdir -p tftp/ipxe
	cp $^ $@

tftp/ipxe/snp-hua.efi:
	mkdir -p tftp/ipxe
# we dont build the snp-hua.efi binary. It's checked into git, so here we just copy it over
	cp ipxe/bin/snp-hua.efi $@

ipxe/ipxe/build/${ipxev}.tar.gz: ipxev.mk ## Download iPXE source tarball
	mkdir -p $(@D)
	curl -fL https://github.com/ipxe/ipxe/archive/${ipxev}.tar.gz > $@
	echo "${ipxeh}  $@" | sha512sum -c

# given  t=$(patsubst ipxe/ipxe/build/%,%,$@)
# and   $@=ipxe/ipxe/build/*/*
# t       =                */*
OSFLAG:= $(shell go env GOHOSTOS)
ipxe/ipxe/build/bin-arm64-efi/snp.efi ipxe/ipxe/build/bin-x86_64-efi/ipxe.efi ipxe/ipxe/build/bin/undionly.kpxe ipxe/ipxe/build/bin-test/ipxe.lkrn: ipxe/ipxe/build/${ipxev}.tar.gz ipxe/ipxe/build.sh ${ipxeconfigs}
ifeq (${OSFLAG},darwin)
	docker run -it --rm -v ${PWD}:/code -w /code nixos/nix nix-shell --command "make -j2 ipxe/ipxe/build/bin-arm64-efi/snp.efi ipxe/ipxe/build/bin-x86_64-efi/ipxe.efi ipxe/ipxe/build/bin/undionly.kpxe ipxe/ipxe/build/bin-test/ipxe.lkrn"
else
	+t=$(patsubst ipxe/ipxe/build/%,%,$@)
	rm -rf $(@D)
	mkdir -p $(@D)
	tar -xzf $< -C $(@D)
	cp ${ipxeconfigs} $(@D)
	cd $(@D) && ../../build.sh $$t ${ipxev}
endif

.PHONY: ipxe/tests ipxe/test-%
ipxe/tests: ipxe/test-sanboot
# order of dependencies matters here
ipxe/test-%: ipxe/test/%.expect ipxe/ipxe/build/bin-test/ipxe.lkrn ipxe/test/ ipxe/test/%.pxe
	expect -f $^

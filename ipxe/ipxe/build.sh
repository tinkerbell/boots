#!/usr/bin/env bash

set -eu

# Deps on ubuntu
# apt-get -y --no-install-recommends install build-essential gcc-aarch64-linux-gnu git liblzma-dev

build=$1
version=$2
short_version="$(echo "$version" | cut -c1-5)"

topdir="ipxe-$version"
cp ./*.h "$topdir/src/config/local"
sed -i '/#define OCSP_CHECK/ d' "$topdir/src/config/crypto.h"

set -x
case $build in
bin/undionly.kpxe | bin/ipxe.lkrn)
	rm "$topdir/src/config/local/isa.h"
	cp "$topdir/src/config/local/general.undionly.h" "$topdir/src/config/local/general.h"
	;;
bin-x86_64-efi/ipxe.efi)
	cp "$topdir/src/config/local/general.efi.h" "$topdir/src/config/local/general.h"
	;;
bin-x86_64-efi/snp.efi)
	cp "$topdir/src/config/local/general.efi.h" "$topdir/src/config/local/general.h"
	;;
bin-arm64-efi/snp.efi)
	rm "$topdir/src/config/local/isa.h"
	cp "$topdir/src/config/local/general.efi.h" "$topdir/src/config/local/general.h"
	# http://lists.ipxe.org/pipermail/ipxe-devel/2018-August/006254.html
	sed -i '/^WORKAROUND_CFLAGS/ s|^|#|' "$topdir/src/arch/arm64/Makefile"
	if [[ -z ${CROSS_COMPILE:-} ]]; then
		export CROSS_COMPILE=aarch64-unknown-linux-gnu-
	fi
	;;
*) echo "unknown target: $1" >&2 && exit 1 ;;
esac

rm "$topdir"/src/config/local/general.*.h
make -C "$topdir/src" VERSION_PATCH=255 EXTRAVERSION="+ ($short_version)" "$build"
cp "$topdir/src/$build" .

# Boots

[![Build Status](https://github.com/tinkerbell/boots/workflows/For%20each%20commit%20and%20PR/badge.svg)](https://github.com/tinkerbell/boots/actions?query=workflow%3A%22For+each+commit+and+PR%22+branch%3Amaster)
![](https://img.shields.io/badge/Stability-Experimental-red.svg)

This services handles DHCP, PXE, tftp, and iPXE for provisions.

This repository is [Experimental](https://github.com/packethost/standards/blob/master/experimental-statement.md) meaning that it's based on untested ideas or techniques and not yet established or finalized or involves a radically new and innovative style!
This means that support is best effort (at best!) and we strongly encourage you to NOT use this in production.

## Running Boots

As boots runs a DHCP server, it's often asked if it is safe to run without any network isolation; the answer is yes. While boots does run a DHCP server, it only allocates an IP address when it recognizes the mac address of the requesting device.

### Local Setup

First, you need to make sure you have [git-lfs](https://github.com/git-lfs/git-lfs/wiki/Installation) installed:

```
# install "git-lfs" package for your OS. On Ubuntu, for instance:
# curl https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
# apt install git-lfs

# then run these two commands:
git lfs install
git lfs pull
```

Running the Tests

```
# make the files
make all
# run the tests
go test
```

Build/Run Boots

```
# run boots
./boots
```

You can use NixOS shell, which will have the Git-LFS, Go and others

`nix-shell`

Note: for mac users, you will need to comment out the line `pkgsCross.aarch64-multiplatform.buildPackages.gcc` in order for the build to work

## Website

For complete documentation, please visit the Tinkerbell project hosted at [tinkerbell.org](https://tinkerbell.org).

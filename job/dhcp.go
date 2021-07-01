package job

import (
	"strings"

	dhcp4 "github.com/packethost/dhcp4-go"
	"github.com/pkg/errors"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/dhcp"
	"github.com/tinkerbell/boots/ipxe"
	"github.com/tinkerbell/boots/packet"
)

func IsSpecialOS(i *packet.Instance) bool {
	if i == nil {
		return false
	}
	var slug string
	if i.OSV.Slug != "" {
		slug = i.OSV.Slug
	}
	if i.OS.Slug != "" {
		slug = i.OS.Slug
	}
	return slug == "custom_ipxe" || slug == "custom" || strings.HasPrefix(slug, "vmware") || strings.HasPrefix(slug, "nixos")
}

// ServeDHCP responds to DHCP packets
func (j Job) ServeDHCP(w dhcp4.ReplyWriter, req *dhcp4.Packet) bool {

	// If we are not the chosen provisioner for this piece of hardware
	// do not respond to the DHCP request
	if !j.areWeProvisioner() {
		return false
	}

	// setup reply
	reply := dhcp.NewReply(w, req)
	if reply == nil {
		return false
	}

	// configure DHCP
	if !j.configureDHCP(reply.Packet(), req) {
		j.Error(errors.New("unable to configure DHCP for yiaddr and DHCP options"))
		return false
	}

	// send the DHCP response
	if err := reply.Send(); err != nil {
		j.Error(errors.WithMessage(err, "unable to send DHCP reply"))
		return false
	}
	return true
}

func (j Job) configureDHCP(rep, req *dhcp4.Packet) bool {
	if !j.dhcp.ApplyTo(rep) {
		return false
	}
	if dhcp.SetupPXE(rep, req) {
		isARM := dhcp.IsARM(req)
		if dhcp.Arch(req) != j.Arch() {
			j.With("dhcp", dhcp.Arch(req), "job", j.Arch()).Info("arch mismatch, using dhcp")
		}

		isUEFI := dhcp.IsUEFI(req)
		if isUEFI != j.IsUEFI() {
			j.With("dhcp", isUEFI, "job", j.IsUEFI()).Info("uefi mismatch, using dhcp")
		}

		isSNP := dhcp.IsSNP(req)

		isPacket := ipxe.IsPacketIPXE(req)
		if isPacket {
			ipxe.Setup(rep)
		}

		j.setPXEFilename(rep, isPacket, isARM, isUEFI, isSNP)
	}
	return true
}

func (j Job) isPXEAllowed() bool {
	if j.hardware.HardwareAllowPXE(j.mac) {
		return true
	}
	if j.InstanceID() == "" {
		return false
	}
	return j.instance.AllowPXE
}

func (j Job) areWeProvisioner() bool {
	if j.hardware.HardwareProvisioner() == "" {
		return true
	}

	return j.hardware.HardwareProvisioner() == j.ProvisionerEngineName()
}

func (j Job) setPXEFilename(rep *dhcp4.Packet, isPacket, isARM, isUEFI, isSNP bool) {
	if j.HardwareState() == "in_use" {
		if j.InstanceID() == "" {
			j.Error(errors.New("setPXEFilename called on a job with no instance"))
			return
		}

		if j.instance.State != "active" {
			j.With("hardware.state", j.HardwareState(), "instance.state", j.instance.State).Info("device should NOT be trying to PXE boot")
			return
		}

		// ignore custom_ipxe because we always do dhcp for it and we'll want to do /nonexistent filename so
		// nics don't timeout.... but why though?
		if !j.isPXEAllowed() && j.hardware.OperatingSystem().OsSlug != "custom_ipxe" {
			err := errors.New("device should NOT be trying to PXE boot")
			j.With("hardware.state", j.HardwareState(), "allow_pxe", j.isPXEAllowed(), "os", j.hardware.OperatingSystem().OsSlug).Info(err)
			return
		}
		// custom_ipxe or rescue
	}

	var filename string
	var pxeClient bool
	if !isPacket {
		if j.PArch() == "hua" || j.PArch() == "2a2" {
			filename = "snp-hua.efi"
		} else if isARM {
			filename = "snp-nolacp.efi"
		} else if isSNP {
			filename = "snp.efi"
		} else if isUEFI {
			filename = "ipxe.efi"
		} else {
			filename = "undionly.kpxe"
		}
	} else if !j.isPXEAllowed() {
		// Always honor allow_pxe.
		// We set a filename because if a machine is actually trying to PXE and nothing is sent it may hang for
		// a while waiting for any possible ProxyDHCP packets and it would delay booting to disks and phoning-home.
		//
		// Why we wait until here instead of sending the file name early on? I don't know. We should not need to
		// send our iPXE, boot into it, and then send /nonexistent afaik.
		//
		// TODO(mmlb) try to move this logic to much earlier in the function, maybe all the way as the first thing even.

		os := j.OperatingSystem()
		j.With("instance.state", j.instance.State, "os_slug", os.Slug, "os_distro", os.Distro, "os_version", os.Version).Info()
		pxeClient = true
		filename = "/nonexistent"
	} else {
		pxeClient = true
		filename = "http://" + conf.PublicFQDN + "/auto.ipxe"
	}

	if filename == "" {
		err := errors.New("no filename is set")
		j.Error(err)
		return
	}

	dhcp.SetFilename(rep, filename, conf.PublicIPv4, pxeClient)
}

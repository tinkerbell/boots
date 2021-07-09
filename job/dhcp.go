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
		arch := "x86"
		firmware := "bios"

		isARM := dhcp.IsARM(req)
		if dhcp.Arch(req) != j.Arch() {
			j.With("dhcp", dhcp.Arch(req), "job", j.Arch()).Info("arch mismatch, using dhcp")
		}
		if isARM {
			arch = "arm"
			if parch := j.PArch(); parch == "2a2" || parch == "hua" {
				arch = "hua"
			}
		}

		isUEFI := dhcp.IsUEFI(req)
		if isUEFI != j.IsUEFI() {
			j.With("dhcp", isUEFI, "job", j.IsUEFI()).Info("uefi mismatch, using dhcp")
		}
		if isUEFI {
			firmware = "uefi"
		}

		isOuriPXE := ipxe.IsOuriPXE(req)
		if isOuriPXE {
			ipxe.Setup(rep)
		}

		if filename := j.getPXEFilename(arch, firmware, isOuriPXE); filename != "" {
			dhcp.SetFilename(rep, filename, conf.PublicIPv4)
		}
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

func (j Job) getPXEFilename(arch, firmware string, isOuriPXE bool) string {
	if !j.isPXEAllowed() {
		if j.instance != nil && j.instance.State == "active" {
			// We set a filename because if a machine is actually trying to PXE and nothing is sent it may hang for
			// a while waiting for any possible ProxyDHCP packets and it would delay booting from disks.
			// This short cuts all that when we know we want to be booting from disk.
			return "/pxe-is-not-allowed"
		}
		return ""
	}

	var filename string
	if !isOuriPXE {
		switch {
		case arch == "hua":
			filename = "snp-hua.efi"
		case arch == "arm" && firmware == "uefi":
			filename = "snp-nolacp.efi"
		case arch == "x86" && firmware == "uefi":
			filename = "ipxe.efi"
		case arch == "x86" && firmware == "bios":
			filename = "undionly.kpxe"
		}
	} else {
		filename = "http://" + conf.PublicFQDN + "/auto.ipxe"
	}
	return filename
}

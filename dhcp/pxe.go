package dhcp

import (
	"net"
	"strings"

	dhcp4 "github.com/packethost/dhcp4-go"
	"github.com/pkg/errors"
)

var pxeVendorOptions = dhcp4.OptionMap{
	6: []byte{0x8}, // PXE_DISCOVERY_CONTROL: Attempt to tell PXE to boot faster.
}.Serialize()

// from https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml
var procArchTypes = []string{
	"x86 BIOS",
	"NEC/PC98 (DEPRECATED)",
	"Itanium",
	"DEC Alpha (DEPRECATED)",
	"Arc x86 (DEPRECATED)",
	"Intel Lean Client (DEPRECATED)",
	"x86 UEFI",
	"x64 UEFI",
	"EFI Xscale (DEPRECATED)",
	"EBC",
	"ARM 32-bit UEFI",
	"ARM 64-bit UEFI",
	"PowerPC Open Firmware",
	"PowerPC ePAPR",
	"POWER OPAL v3",
	"x86 uefi boot from http",
	"x64 uefi boot from http",
	"ebc boot from http",
	"arm uefi 32 boot from http",
	"arm uefi 64 boot from http",
	"pc/at bios boot from http",
	"arm 32 uboot",
	"arm 64 uboot",
	"arm uboot 32 boot from http",
	"arm uboot 64 boot from http",
	"RISC-V 32-bit UEFI",
	"RISC-V 32-bit UEFI boot from http",
	"RISC-V 64-bit UEFI",
	"RISC-V 64-bit UEFI boot from http",
	"RISC-V 128-bit UEFI",
	"RISC-V 128-bit UEFI boot from http",
	"s390 Basic",
	"s390 Extended",
}

func ProcessorArchType(req *dhcp4.Packet) string {
	v, ok := req.GetUint16(dhcp4.OptionClientSystem)
	if !ok || int(v) >= len(procArchTypes) {
		return ""
	}
	return procArchTypes[v]
}

func Arch(req *dhcp4.Packet) string {
	arch := ProcessorArchType(req)
	switch arch {
	case "x86 BIOS", "x64 UEFI":
		return "x86_64"
	case "ARM 64-bit UEFI":
		return "aarch64"
	default:
		return arch
	}
}

func IsARM(req *dhcp4.Packet) bool {
	return strings.Contains(strings.ToLower(ProcessorArchType(req)), "arm")
}

func IsUEFI(req *dhcp4.Packet) bool {
	return strings.Contains(strings.ToLower(ProcessorArchType(req)), "uefi")
}

func IsSNP(req *dhcp4.Packet) bool {
	return ProcessorArchType(req) == "x64 UEFI"
}

func IsPXE(req *dhcp4.Packet) bool {
	_, ok := req.GetOption(dhcp4.OptionUUIDGUID)
	if ok {
		return ok
	}
	class, ok := req.GetString(dhcp4.OptionClassID)
	return ok && strings.HasPrefix(class, "PXEClient")
}

func SetupPXE(rep, req *dhcp4.Packet) bool {
	if !copyGUID(rep, req) {
		if class, ok := req.GetString(dhcp4.OptionClassID); !ok || !strings.HasPrefix(class, "PXEClient") {
			return false // not a PXE client
		}
		dhcplog.With("mac", req.GetCHAddr(), "xid", req.GetXID()).Info("no client GUID provided")
	}
	rep.SetOption(dhcp4.OptionVendorSpecific, pxeVendorOptions)
	return true
}

func SetFilename(rep *dhcp4.Packet, filename string, nextServer net.IP, pxeClient bool) {
	file := rep.File()
	if len(filename) > len(file) {
		err := errors.New("filename too long, would be truncated")
		// req CHaddr and XID == req's
		dhcplog.With("mac", rep.GetCHAddr(), "xid", rep.GetXID(), "filename", filename).Fatal(err)
	}
	if pxeClient {
		rep.SetString(dhcp4.OptionClassID, "PXEClient")
	}
	rep.SetSIAddr(nextServer) // next-server: IP address of the TFTP/HTTP Server.
	copy(file, filename)      // filename: Executable (or iPXE script) to boot from.
}

func copyGUID(rep, req *dhcp4.Packet) bool {
	if guid, ok := req.GetOption(dhcp4.OptionUUIDGUID); ok {
		if len(guid) != 17 || guid[0] != 0 {
			dhcplog.With("mac", req.GetCHAddr(), "xid", req.GetXID()).Error(errors.New("unsupported or malformed client GUID"))
		} else {
			rep.SetOption(dhcp4.OptionUUIDGUID, guid)
			return true
		}
	}
	return false
}

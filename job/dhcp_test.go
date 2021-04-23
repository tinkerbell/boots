package job

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	assert "github.com/stretchr/testify/require"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/packet"
)

func TestGetPXEFilename(t *testing.T) {
	conf.PublicFQDN = "boots-testing.packet.net"

	var getPXEFilenameTests = []struct {
		name     string
		iState   string
		allowPXE bool
		ouriPXE  bool
		arch     string
		firmware string
		filename string
	}{
		{name: "inactive instance",
			iState: "not_active"},
		{name: "active instance",
			iState:   "active",
			filename: "/pxe-is-not-allowed"},
		{name: "PXE is allowed for non active instance",
			iState: "not_active", allowPXE: true, arch: "x86", firmware: "bios",
			filename: "undionly.kpxe"},
		{name: "our embedded iPXE wants iPXE script",
			ouriPXE: true, allowPXE: true,
			filename: "http://" + conf.PublicFQDN + "/auto.ipxe"},
		{name: "2a2",
			arch: "hua", allowPXE: true,
			filename: "snp-hua.efi"},
		{name: "arm",
			arch: "arm", firmware: "uefi", allowPXE: true,
			filename: "snp-nolacp.efi"},
		{name: "hua",
			arch: "hua", allowPXE: true,
			filename: "snp-hua.efi"},
		{name: "x86 bios",
			arch: "x86", firmware: "bios", allowPXE: true,
			filename: "undionly.kpxe"},
		{name: "x86 uefi",
			arch: "x86", firmware: "uefi", allowPXE: true,
			filename: "ipxe.efi"},
		{name: "unknown arch",
			arch: "riscv", allowPXE: true},
		{name: "unknown firmware",
			arch: "coreboot", allowPXE: true},
	}

	for i, tt := range getPXEFilenameTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("index=%d iState=%q allowPXE=%v ouriPXE=%v arch=%v platfrom=%v filename=%q",
				i, tt.iState, tt.allowPXE, tt.ouriPXE, tt.arch, tt.firmware, tt.filename)

			instance := &packet.Instance{
				ID:    uuid.New().String(),
				State: packet.InstanceState(tt.iState),
			}
			j := Job{
				Logger: joblog.With("index", i, "iState", tt.iState, "allowPXE", tt.allowPXE, "ouriPXE", tt.ouriPXE, "arch", tt.arch, "firmware", tt.firmware, "filename", tt.filename),
				hardware: &packet.HardwareCacher{
					ID:       uuid.New().String(),
					AllowPXE: tt.allowPXE,
					Instance: instance,
				},
				instance: instance,
			}
			filename := j.getPXEFilename(tt.arch, tt.firmware, tt.ouriPXE)
			if tt.filename != filename {
				t.Fatalf("unexpected filename want:%q, got:%q", tt.filename, filename)
			}
		})
	}
}

func TestAllowPXE(t *testing.T) {
	for _, tt := range []struct {
		want     bool
		hw       bool
		instance bool
		iid      string
	}{
		{want: true, hw: true},
		{want: false, hw: false, instance: true},
		{want: true, hw: false, instance: true, iid: "id"},
		{want: false, hw: false, instance: false, iid: "id"},
	} {
		name := fmt.Sprintf("want=%t, hardware=%t, instance=%t, instance_id=%s", tt.want, tt.hw, tt.instance, tt.iid)
		t.Run(name, func(t *testing.T) {
			j := Job{
				hardware: &packet.HardwareCacher{
					AllowPXE: tt.hw,
				},
				instance: &packet.Instance{
					ID:       tt.iid,
					AllowPXE: tt.instance,
				},
			}
			got := j.isPXEAllowed()
			if got != tt.want {
				t.Fatalf("unexpected return, want: %t, got %t", tt.want, got)
			}
		})
	}
}

func TestAreWeProvisioner(t *testing.T) {
	for _, tt := range []struct {
		want              bool
		ProvisionerEngine string
		env               string
	}{
		{want: true, ProvisionerEngine: "tinkerbell", env: "tinkerbell"},
		{want: false, ProvisionerEngine: "tinkerbell", env: "packet"},
		{want: true, ProvisionerEngine: "", env: "packet"},
		{want: false, ProvisionerEngine: "tinkerbell", env: ""},
	} {
		name := fmt.Sprintf("want=%t, ProvisionerEngine=%s env=%s", tt.want, tt.ProvisionerEngine, tt.env)
		t.Run(name, func(t *testing.T) {
			j := Job{
				hardware: &packet.HardwareTinkerbellV1{
					Metadata: packet.Metadata{
						ProvisionerEngine: tt.ProvisionerEngine,
					},
				},
			}
			SetProvisionerEngineName(tt.env)
			got := j.areWeProvisioner()
			if got != tt.want {
				t.Fatalf("unexpected return, want: %t, got %t", tt.want, got)
			}
		})
	}
}

func TestIsSpecialOS(t *testing.T) {
	t.Run("nil instance", func(t *testing.T) {
		special := IsSpecialOS(nil)
		assert.Equal(t, false, special)
	})

	for name, want := range map[string]bool{
		"custom_ipxe": true,
		"custom":      true,
		"vmware_foo":  true,
		"nixos_foo":   true,
		"flatcar_foo": false,
	} {
		t.Run("OS-"+name, func(t *testing.T) {
			instance := &packet.Instance{
				OS: &packet.OperatingSystem{
					Slug: name,
				},
				OSV: &packet.OperatingSystem{},
			}
			got := IsSpecialOS(instance)
			assert.Equal(t, want, got)
		})
		t.Run("OSV-"+name, func(t *testing.T) {
			instance := &packet.Instance{
				OS: &packet.OperatingSystem{},
				OSV: &packet.OperatingSystem{
					Slug: name,
				},
			}
			got := IsSpecialOS(instance)
			assert.Equal(t, want, got)
		})
	}
}

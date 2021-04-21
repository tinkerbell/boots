package job

import (
	"bytes"
	"fmt"
	"testing"

	dhcp4 "github.com/packethost/dhcp4-go"
	assert "github.com/stretchr/testify/require"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/packet"
)

func TestSetPXEFilename(t *testing.T) {
	conf.PublicFQDN = "boots-testing.packet.net"

	var setPXEFilenameTests = []struct {
		name     string
		hState   string
		id       string
		iState   string
		slug     string
		plan     string
		allowPXE bool
		packet   bool
		arm      bool
		uefi     bool
		filename string
	}{
		{name: "in_use: just in_use",
			hState: "in_use"},
		{name: "in_use: no instance state",
			hState: "in_use", id: "$instance_id", iState: ""},
		{name: "in_use: instance not active",
			hState: "in_use", id: "$instance_id", iState: "not_active"},
		{name: "in_use: instance active",
			hState: "in_use", id: "$instance_id", iState: "active"},
		{name: "in_use: active not custom ipxe",
			hState: "in_use", id: "$instance_id", iState: "active", slug: "not_custom_ipxe"},
		{name: "in_use: active custom ipxe",
			hState: "in_use", id: "$instance_id", iState: "active", allowPXE: true, slug: "custom_ipxe",
			filename: "undionly.kpxe"},
		{name: "in_use: active custom ipxe with allow pxe",
			hState: "in_use", id: "$instance_id", iState: "active", allowPXE: true,
			filename: "undionly.kpxe"},
		{name: "hua",
			plan: "hua", allowPXE: true,
			filename: "snp-hua.efi"},
		{name: "2a2",
			plan: "2a2", allowPXE: true,
			filename: "snp-hua.efi"},
		{name: "arm",
			arm: true, allowPXE: true,
			filename: "snp-nolacp.efi"},
		{name: "x86 uefi",
			uefi: true, allowPXE: true,
			filename: "ipxe.efi"},
		{name: "all defaults",
			allowPXE: true,
			filename: "undionly.kpxe"},
		{name: "PXE not allowed",
			filename: "/pxe-is-not-allowed"},
		{name: "packet iPXE PXE allowed",
			packet: true, id: "$instance_id", allowPXE: true, filename: "http://" + conf.PublicFQDN + "/auto.ipxe"},
	}

	for i, tt := range setPXEFilenameTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("index=%d hState=%q id=%q iState=%q slug=%q plan=%q allowPXE=%v packet=%v arm=%v uefi=%v filename=%q",
				i, tt.hState, tt.id, tt.iState, tt.slug, tt.plan, tt.allowPXE, tt.packet, tt.arm, tt.uefi, tt.filename)

			if tt.plan == "" {
				tt.plan = "0"
			}

			instance := &packet.Instance{
				ID:    tt.id,
				State: packet.InstanceState(tt.iState),
				OSV: &packet.OperatingSystem{
					OsSlug: tt.slug,
				},
			}
			j := Job{
				Logger: joblog.With("index", i, "hState", tt.hState, "id", tt.id, "iState", tt.iState, "slug", tt.slug, "plan", tt.plan, "allowPXE", tt.allowPXE, "packet", tt.packet, "arm", tt.arm, "uefi", tt.uefi, "filename", tt.filename),
				hardware: &packet.HardwareCacher{
					ID:       "$hardware_id",
					AllowPXE: tt.allowPXE,
					State:    packet.HardwareState(tt.hState),
					PlanSlug: "baremetal_" + tt.plan,
					Instance: instance,
				},
				instance: instance,
			}
			rep := dhcp4.NewPacket(42)
			j.setPXEFilename(&rep, tt.packet, tt.arm, tt.uefi)
			filename := string(bytes.TrimRight(rep.File(), "\x00"))

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

package packet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"

	"github.com/packethost/cacher/protos/cacher"
	tpkg "github.com/tinkerbell/tink/pkg"
	tink "github.com/tinkerbell/tink/protos/hardware"
	tw "github.com/tinkerbell/tink/protos/workflow"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tinkerbell/boots/metrics"
)

const mimeJSON = "application/json"

type Component struct {
	Type            string      `json:"type"`
	Name            string      `json:"name"`
	Vendor          string      `json:"vendor"`
	Model           string      `json:"model"`
	Serial          string      `json:"serial"`
	FirmwareVersion string      `json:"firmware_version"`
	Data            interface{} `json:"data"`
}

type ComponentsResponse struct {
	Components []Component `json:"components"`
}

// GetWorkflowsFromTink fetches the list of workflows from tink
func (c *Client) GetWorkflowsFromTink(hwID HardwareID) (result *tw.WorkflowContextList, err error) {
	if hwID == "" {
		return result, errors.New("missing hardware id")
	}

	labels := prometheus.Labels{"from": "dhcp"}
	cacherTimer := prometheus.NewTimer(metrics.CacherDuration.With(labels))
	metrics.CacherRequestsInProgress.With(labels).Inc()
	metrics.CacherTotal.With(labels).Inc()

	result, err = c.workflowClient.GetWorkflowContextList(context.Background(), &tw.WorkflowContextRequest{WorkerId: hwID.String()})

	cacherTimer.ObserveDuration()
	metrics.CacherRequestsInProgress.With(labels).Dec()

	if err != nil {
		return result, errors.Wrap(err, "error while fetching the workflow")
	}

	return result, nil
}

func (c *Client) DiscoverHardwareFromDHCP(mac net.HardwareAddr, giaddr net.IP, circuitID string) (Discovery, error) {
	if mac == nil {
		return nil, errors.New("missing MAC address")
	}

	labels := prometheus.Labels{"from": "dhcp"}
	cacherTimer := prometheus.NewTimer(metrics.CacherDuration.With(labels))
	metrics.CacherRequestsInProgress.With(labels).Inc()
	metrics.CacherTotal.With(labels).Inc()

	dataModelVersion := os.Getenv("DATA_MODEL_VERSION")
	switch dataModelVersion {
	case "":
		cc := c.hardwareClient.(cacher.CacherClient)
		msg := &cacher.GetRequest{
			MAC: mac.String(),
		}

		resp, err := cc.ByMAC(context.Background(), msg)

		cacherTimer.ObserveDuration()
		metrics.CacherRequestsInProgress.With(labels).Dec()

		if err != nil {
			return nil, errors.Wrap(err, "get hardware by mac from cacher")
		}

		b := []byte(resp.JSON)
		if string(b) != "" {
			metrics.CacherCacheHits.With(labels).Inc()
			return NewDiscovery(b)
		}
	case "1":
		tc := c.hardwareClient.(tink.HardwareServiceClient)
		msg := &tink.GetRequest{
			Mac: mac.String(),
		}

		resp, err := tc.ByMAC(context.Background(), msg)

		cacherTimer.ObserveDuration()
		metrics.CacherRequestsInProgress.With(labels).Dec()

		if err != nil {
			return nil, errors.Wrap(err, "get hardware by mac from tink")
		}

		b, err := json.Marshal(&tpkg.HardwareWrapper{Hardware: resp}) // uses HardwareWrapper for its custom marshaler
		if err != nil {
			return nil, errors.New("marshalling tink hardware")
		}

		if string(b) != "{}" {
			metrics.CacherCacheHits.With(labels).Inc()
			return NewDiscovery(b)
		}

		return nil, errors.New("not found")
	default:
		return nil, errors.New("unknown DATA_MODEL_VERSION")
	}

	if giaddr == nil {
		return nil, errors.New("missing MAC address")
	}

	metrics.HardwareDiscovers.With(labels).Inc()
	metrics.DiscoversInProgress.With(labels).Inc()
	defer metrics.DiscoversInProgress.With(labels).Dec()
	discoverTimer := prometheus.NewTimer(metrics.DiscoverDuration.With(labels))
	defer discoverTimer.ObserveDuration()

	req := struct {
		MAC       string `json:"mac"`
		GIADDR    string `json:"giaddr,omitempty"`
		CIRCUITID string `json:"circuit_id,omitempty"`
	}{
		MAC:       mac.String(),
		GIADDR:    giaddr.String(),
		CIRCUITID: circuitID,
	}

	b, err := json.Marshal(&req)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshalling api discovery")
	}

	c.logger.With("giaddr", req.GIADDR, "mac", req.MAC).Debug("hardware discovery by mac")

	var res DiscoveryCacher
	if err := c.Post("/staff/cacher/hardware-discovery", mimeJSON, bytes.NewReader(b), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) DiscoverHardwareFromIP(ip net.IP) (Discovery, error) {
	if ip.String() == net.IPv4zero.String() {
		return nil, errors.New("missing ip address")
	}

	labels := prometheus.Labels{"from": "ip"}
	cacherTimer := prometheus.NewTimer(metrics.CacherDuration.With(labels))
	defer cacherTimer.ObserveDuration()
	metrics.CacherRequestsInProgress.With(labels).Inc()
	defer metrics.CacherRequestsInProgress.With(labels).Dec()

	var b []byte
	dataModelVersion := os.Getenv("DATA_MODEL_VERSION")
	switch dataModelVersion {
	case "":
		cc := c.hardwareClient.(cacher.CacherClient)
		msg := &cacher.GetRequest{
			IP: ip.String(),
		}

		resp, err := cc.ByIP(context.Background(), msg)

		cacherTimer.ObserveDuration()
		metrics.CacherRequestsInProgress.With(labels).Dec()

		if err != nil {
			return nil, errors.Wrap(err, "get hardware by ip from cacher")
		}

		b = []byte(resp.JSON)
	case "1":
		tc := c.hardwareClient.(tink.HardwareServiceClient)
		msg := &tink.GetRequest{
			Ip: ip.String(),
		}

		resp, err := tc.ByIP(context.Background(), msg)

		cacherTimer.ObserveDuration()
		metrics.CacherRequestsInProgress.With(labels).Dec()

		if err != nil {
			return nil, errors.Wrap(err, "get hardware by ip from tink")
		}

		b, err = json.Marshal(&tpkg.HardwareWrapper{Hardware: resp}) // uses HardwareWrapper for its custom marshaler
		if err != nil {
			return nil, errors.New("marshalling tink hardware")
		}
	default:
		return nil, errors.New("unknown DATA_MODEL_VERSION")
	}

	return NewDiscovery(b)
}

// GetDeviceIDFromIP Looks up a device (instance) in cacher via ByIP
func (c *Client) GetInstanceIDFromIP(dip net.IP) (string, error) {
	d, err := c.DiscoverHardwareFromIP(dip)
	if err != nil {
		return "", err
	}
	if d.Instance() == nil {
		return "", nil
	}
	return d.Instance().ID, nil
}

// PostHardwareComponent - POSTs a HardwareComponent to the API
func (c *Client) PostHardwareComponent(hardwareID HardwareID, body io.Reader) (*ComponentsResponse, error) {
	var response ComponentsResponse

	if err := c.Post("/hardware/"+hardwareID.String()+"/components", mimeJSON, body, &response); err != nil {
		return nil, err
	}

	return &response, nil
}
func (c *Client) PostHardwareEvent(id string, body io.Reader) (string, error) {
	var res struct {
		ID string `json:"id"`
	}
	if err := c.Post("/hardware/"+id+"/events", mimeJSON, body, &res); err != nil {
		return "", err
	}
	return res.ID, nil
}
func (c *Client) PostHardwarePhoneHome(id string) error {
	return c.Post("/hardware/"+id+"/phone-home", "", nil, nil)
}
func (c *Client) PostHardwareFail(id string, body io.Reader) error {
	return c.Post("/hardware/"+id+"/fail", mimeJSON, body, nil)
}
func (c *Client) PostHardwareProblem(id HardwareID, body io.Reader) (string, error) {
	var res struct {
		ID string `json:"id"`
	}
	if err := c.Post("/hardware/"+id.String()+"/problems", mimeJSON, body, &res); err != nil {
		return "", err
	}
	return res.ID, nil
}

func (c *Client) PostInstancePhoneHome(id string) error {
	return c.Post("/devices/"+id+"/phone-home", "", nil, nil)
}
func (c *Client) PostInstanceEvent(id string, body io.Reader) (string, error) {
	var res struct {
		ID string `json:"id"`
	}
	if err := c.Post("/devices/"+id+"/events", mimeJSON, body, &res); err != nil {
		return "", err
	}
	return res.ID, nil
}
func (c *Client) PostInstanceFail(id string, body io.Reader) error {
	return c.Post("/devices/"+id+"/fail", mimeJSON, body, nil)
}
func (c *Client) PostInstancePassword(id, pass string) error {
	var req = struct {
		Password string `json:"password"`
	}{
		Password: pass,
	}

	b, err := json.Marshal(&req)
	if err != nil {
		return errors.Wrap(err, "marshalling instance password")
	}

	return c.Post("/devices/"+id+"/password", mimeJSON, bytes.NewReader(b), nil)
}
func (c *Client) UpdateInstance(id string, body io.Reader) error {
	return c.Patch("/devices/"+id, mimeJSON, body, nil)
}

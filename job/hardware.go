package job

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
)

// Component models a single hardware component
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

// AddHardware - Add hardware component(s)
func (j Job) AddHardware(w http.ResponseWriter, req *http.Request) {
	b, err := readClose(req.Body)
	if err != nil {
		j.Logger.Error(errors.Wrap(err, "reading hardware component body"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var response ComponentsResponse

	if err := json.Unmarshal(b, &response); err != nil {
		j.Logger.Error(errors.Wrap(err, "parsing hardware component as json"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	jsonBody, err := json.Marshal(response)
	if err != nil {
		j.Logger.Error(errors.Wrap(err, "marshalling componenents as json"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, err := client.PostHardwareComponent(j.hardware.HardwareID(), bytes.NewReader(jsonBody)); err != nil {
		j.Logger.Error(errors.Wrap(err, "posting componenents"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte{})
}

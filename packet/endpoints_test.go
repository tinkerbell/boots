package packet

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/packethost/cacher/protos/cacher"
	"github.com/packethost/pkg/log"
	"github.com/pkg/errors"
	assert "github.com/stretchr/testify/require"
	metrics "github.com/tinkerbell/boots/metrics"
	cacherMock "github.com/tinkerbell/boots/packet/mock_cacher"
	workflowMock "github.com/tinkerbell/boots/packet/mock_workflow"
	tw "github.com/tinkerbell/tink/protos/workflow"
)

func TestMain(m *testing.M) {
	metrics.Init(log.Logger{})
	os.Exit(m.Run())
}

func TestDiscoverHardwareFromDHCP(t *testing.T) {
	logger, _ := log.Init("tests")

	for _, test := range []struct {
		name      string
		err       error
		gResponse string
		code      int
		hResponse string
		id        HardwareID
	}{
		{name: "has grpc error",
			err: errors.New("some error"),
		},
		{name: "data in cacher",
			gResponse: `{"id":"%s"}`,
		},
		{name: "data in packet api",
			hResponse: `{"id":"%s"}`,
		},
		{name: "unknown",
			hResponse: "{}",
			code:      http.StatusNotFound},
	} {

		t.Run(test.name, func(t *testing.T) {
			id := uuid.New()
			if test.gResponse != "" {
				test.gResponse = fmt.Sprintf(test.gResponse, id)
			}
			if strings.Contains(test.hResponse, "%") {
				test.hResponse = fmt.Sprintf(test.hResponse, id)
			}

			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.code != 0 {
					w.WriteHeader(test.code)
				}
				fmt.Fprintln(w, test.hResponse)
			}))
			defer s.Close()
			u, _ := url.Parse(s.URL)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			cMock := cacherMock.NewMockCacherClient(ctrl)
			cMock.EXPECT().ByMAC(gomock.Any(), gomock.Any()).Return(&cacher.Hardware{JSON: test.gResponse}, test.err)

			c := &Client{
				baseURL:        u,
				http:           s.Client(),
				hardwareClient: cMock,
				logger:         logger,
			}
			m, _ := net.ParseMAC("00:00:ba:dd:be:ef")
			d, err := c.DiscoverHardwareFromDHCP(m, net.ParseIP("127.0.0.1"), "")
			if test.err != nil || test.code != 0 {
				assert.Error(t, err)
				assert.Nil(t, d)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, d)
			assert.IsType(t, &DiscoveryCacher{}, d)
			assert.Equal(t, HardwareID(id.String()), d.Hardware().HardwareID())
		})
	}
}

func TestGetWorkflowsFromTink(t *testing.T) {
	for _, test := range []struct {
		name string
		hwID HardwareID
		wcl  *tw.WorkflowContextList
		err  error
	}{
		{name: "test hardware workflow",
			hwID: "Hardware-fake-bde9-812726eff314",
			wcl: &tw.WorkflowContextList{
				WorkflowContexts: []*tw.WorkflowContext{
					{
						WorkflowId:         "active-fake-workflow-bde9-812726eff314",
						CurrentActionState: 0,
					},
				},
			},
			err: nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ht := &httptest.Server{URL: "FakeURL"}
			u, err := url.Parse(ht.URL)
			if err != nil {
				t.Fatal(err)
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			cMock := workflowMock.NewMockWorkflowServiceClient(ctrl)
			cMock.EXPECT().GetWorkflowContextList(gomock.Any(), gomock.Any()).Return(test.wcl, test.err)

			c := NewMockClient(u, cMock)
			w, err := c.GetWorkflowsFromTink(test.hwID)
			if test.err != nil {
				assert.Error(t, err)
				return
			}
			assert.Equal(t, w, test.wcl)
		})
	}
}

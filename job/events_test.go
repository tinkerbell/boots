package job

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/tinkerbell/boots/packet"
)

func TestPhoneHome(t *testing.T) {
	var reqs []req
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()

		switch r.Method {
		case http.MethodPost, http.MethodPatch:
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
		reqs = append(reqs, req{r.Method, r.URL.String(), string(body)})
		fmt.Println()

		w.Write([]byte(`{"id":"event-id"}`))
	}))
	defer ts.Close()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	SetClient(packet.NewMockClient(u))

	for name, test := range phoneHomeTests {
		fmt.Println("test:", name)
		t.Log("test:", name)
		reqs = nil

		j := Job{
			Logger: joblog.With("test", name),
			mode:   modeInstance,
			hardware: &packet.Hardware{
				ID:    "$hardware_id",
				State: packet.HardwareState(test.state),
			},
			instance: &packet.Instance{
				ID: test.id,
				OS: packet.OperatingSystem{
					OsSlug: test.os,
				},
			},
		}
		bad := !j.phoneHome([]byte(test.event))
		if bad != test.bad {
			t.Fatalf("mismatch in expected return from phoneHome, want:%t, got:%t", test.bad, bad)
		}
		if bad {
			continue
		}

		/*
			fmt.Println("reqs:")
			for _, req := range reqs {
				fmt.Println(req)
			}
		*/
		if len(test.reqs) != len(reqs) {
			t.Fatalf("mismatch of api requests want:%d got:%d", len(test.reqs), len(reqs))
		}
		for i := range reqs {
			want := test.reqs[i]
			got := reqs[i]
			if want.url != got.url {
				t.Fatalf("mismatch of url in api request want:%q, got:%q", want.url, got.url)
			}
			if want.body != got.body {
				t.Fatalf("mismatch of body in api request want:%q, got:%q", want.body, got.body)
			}
		}
	}
}

type req struct{ method, url, body string }
type reqs []req

var phoneHomeTests = map[string]struct {
	id    string
	event string
	reqs  reqs
	os    string
	bad   bool
	state string
}{
	"bad body": {
		id:    "$instance_id",
		event: "{",
		bad:   true,
	},
	"empty body": {
		id:    "$instance_id",
		event: "",
		reqs:  reqs{{"POST", "/devices/$instance_id/phone-home", ""}},
	},
	"custom_ipxe done": {
		id:    "$instance_id",
		event: `{"type":"provisioning.104.01"}`,
		os:    "custom_ipxe",
		reqs: reqs{
			{"POST", "/devices/$instance_id/events", `{"type":"provisioning.104.01"}`},
			{"PATCH", "/devices/$instance_id", `{"allow_pxe":false}`},
			{"POST", "/devices/$instance_id/phone-home", ``},
		},
	},
	"no id, not preinstalling": {
		event: `{"type":"provisioning.104.01"}`,
		bad:   true,
	},
	"preinstalling": {
		state: "preinstalling",
		event: `{"type":"provisioning.109"}`,
		reqs: reqs{
			{"POST", "/hardware/$hardware_id/events", `{"type":"provisioning.109"}`},
		},
	},
}

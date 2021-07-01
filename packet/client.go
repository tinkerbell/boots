package packet

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"runtime"

	cacherClient "github.com/packethost/cacher/client"
	"github.com/packethost/pkg/env"
	"github.com/packethost/pkg/log"
	"github.com/pkg/errors"
	"github.com/tinkerbell/boots/httplog"
	tinkClient "github.com/tinkerbell/tink/client"
	tw "github.com/tinkerbell/tink/protos/workflow"
)

type hardwareGetter interface {
}

// Client has all the fields corresponding to connection
type Client struct {
	http           *http.Client
	baseURL        *url.URL
	consumerToken  string
	authToken      string
	hardwareClient hardwareGetter
	workflowClient tw.WorkflowServiceClient
	logger         log.Logger
}

func NewClient(logger log.Logger, consumerToken, authToken string, baseURL *url.URL) (*Client, error) {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected type for http.DefaultTransport")

	}

	transport := t.Clone()
	transport.MaxIdleConnsPerHost = env.Int("BOOTS_HTTP_HOST_CONNECTIONS", runtime.GOMAXPROCS(0)/2)

	c := &http.Client{
		Transport: &httplog.Transport{
			RoundTripper: transport,
		},
	}

	var hg hardwareGetter
	var wg tw.WorkflowServiceClient
	var err error
	dataModelVersion := os.Getenv("DATA_MODEL_VERSION")
	switch dataModelVersion {
	case "1":
		hg, err = tinkClient.TinkHardwareClient()
		if err != nil {
			return nil, errors.Wrap(err, "connect to tink")
		}

		wg, err = tinkClient.TinkWorkflowClient()
		if err != nil {
			return nil, errors.Wrap(err, "connect to tink")
		}
	default:
		facility := os.Getenv("FACILITY_CODE")
		if facility == "" {
			return nil, errors.New("FACILITY_CODE env must be set")
		}

		hg, err = cacherClient.New(facility)
		if err != nil {
			return nil, errors.Wrap(err, "connect to cacher")
		}
	}

	return &Client{
		http:           c,
		baseURL:        baseURL,
		consumerToken:  consumerToken,
		authToken:      authToken,
		hardwareClient: hg,
		workflowClient: wg,
		logger:         logger,
	}, nil
}

func NewMockClient(baseURL *url.URL, workflowClient tw.WorkflowServiceClient) *Client {
	t := &httplog.Transport{
		RoundTripper: http.DefaultTransport,
	}
	c := &http.Client{
		Transport: t,
	}
	return &Client{
		http:           c,
		workflowClient: workflowClient,
		baseURL:        baseURL,
	}
}

func (c *Client) Do(req *http.Request, v interface{}) error {
	req.URL = c.baseURL.ResolveReference(req.URL)
	c.addHeaders(req)

	res, err := c.http.Do(req)
	if err != nil {
		return errors.Wrap(err, "submit http request")
	}
	return unmarshalResponse(res, v)
}

func (c *Client) Get(ref string, v interface{}) error {
	req, err := http.NewRequest("GET", ref, nil)
	if err != nil {
		return errors.Wrap(err, "setup GET request")
	}
	return c.Do(req, v)
}

func (c *Client) Patch(ref, mime string, body io.Reader, v interface{}) error {
	req, err := http.NewRequest("PATCH", ref, body)
	if err != nil {
		return errors.Wrap(err, "setup PATCH request")
	}
	if mime != "" {
		req.Header.Set("Content-Type", mime)
	}
	return c.Do(req, v)
}

func (c *Client) Post(ref, mime string, body io.Reader, v interface{}) error {
	req, err := http.NewRequest("POST", ref, body)
	if err != nil {
		return errors.Wrap(err, "setup POST request")
	}
	if mime != "" {
		req.Header.Set("Content-Type", mime)
	}
	return c.Do(req, v)
}

func (c *Client) addHeaders(req *http.Request) {
	h := req.Header
	h.Set("X-Packet-Staff", "1")

	if c.consumerToken != "" {
		h.Set("X-Consumer-Token", c.consumerToken)
	}

	if c.authToken != "" {
		h.Set("X-Auth-Token", c.authToken)
	}
}

func unmarshalResponse(res *http.Response, result interface{}) error {
	defer res.Body.Close()
	defer io.Copy(ioutil.Discard, res.Body) // ensure all of the body is read so we can quickly reuse connection

	if res.StatusCode < 200 || res.StatusCode > 399 {
		e := &httpError{
			StatusCode: res.StatusCode,
		}
		e.unmarshalErrors(res.Body)
		return errors.Wrap(e, "unmarshalling response")
	}

	var err error
	if result == nil {
		return nil
	}

	err = errors.Wrap(json.NewDecoder(res.Body).Decode(result), "decode json body")
	if err == nil {
		return nil
	}

	return errors.Wrap(&httpError{
		StatusCode: res.StatusCode,
		Errors:     []error{err},
	}, "unmarshalling response")
}

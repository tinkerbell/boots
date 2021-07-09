package main

import (
	"flag"
	"io"
	"net"
	"os"
	"path"

	"github.com/avast/retry-go"
	"github.com/packethost/pkg/log"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/job"
	"github.com/tinkerbell/boots/metrics"
	tftp "github.com/tinkerbell/tftp-go"
)

var (
	tftpAddr = conf.TFTPBind
)

func init() {
	flag.StringVar(&tftpAddr, "tftp-addr", tftpAddr, "IP and port to listen on for TFTP.")
}

// ServeTFTP is a useless comment
func ServeTFTP() {
	err := retry.Do(
		func() error {
			return errors.Wrap(tftp.ListenAndServe(tftpAddr, tftpHandler{}), "serving tftp")
		},
	)
	if err != nil {
		mainlog.Fatal(errors.Wrap(err, "retry tftp serve"))
	}
}

type tftpHandler struct {
}

func (tftpHandler) ReadFile(c tftp.Conn, filename string) (tftp.ReadCloser, error) {
	labels := prometheus.Labels{"from": "tftp", "op": "read"}
	metrics.JobsTotal.With(labels).Inc()
	metrics.JobsInProgress.With(labels).Inc()
	timer := prometheus.NewTimer(metrics.JobDuration.With(labels))
	defer timer.ObserveDuration()
	defer metrics.JobsInProgress.With(labels).Dec()

	ip := tftpClientIP(c.RemoteAddr())
	filename = path.Base(filename)
	l := mainlog.With("client", ip.String(), "event", "open", "filename", filename)

	j, err := job.CreateFromRemoteAddr(ip.String())
	if err != nil {
		l.With("error", errors.WithMessage(err, "retrieved job is empty")).Info()
		return serveFakeReader(l, filename)
	}

	// This gates serving PXE file by
	// 1. the existence of a hardware record in tink server
	// AND
	// 2. the network.interfaces[].netboot.allow_pxe value, in the tink server hardware record, equal to true
	// This allows serving custom ipxe scripts, starting up into OSIE or other installation environments
	// without a tink workflow present.
	if !j.AllowPxe() {
		l.Info("the hardware data for this machine, or lack there of, does not allow it to pxe; allow_pxe: false")
		return serveFakeReader(l, filename)
	}

	return j.ServeTFTP(filename, ip.String())
}

func serveFakeReader(l log.Logger, filename string) (tftp.ReadCloser, error) {
	switch filename {
	case "test.1mb":
		l.With("tftp_fake_read", true).Info()
		return &fakeReader{1 * 1024 * 1024}, nil
	case "test.8mb":
		l.With("tftp_fake_read", true).Info()
		return &fakeReader{8 * 1024 * 1024}, nil
	}
	l.With("error", errors.Wrap(os.ErrPermission, "access_violation")).Info()
	return nil, os.ErrPermission
}

func (tftpHandler) WriteFile(c tftp.Conn, filename string) (tftp.WriteCloser, error) {
	ip := tftpClientIP(c.RemoteAddr())
	err := errors.Wrap(os.ErrPermission, "access_violation")
	mainlog.With("client", ip, "event", "create", "filename", filename, "error", err).Info()
	return nil, os.ErrPermission
}

func tftpClientIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		err = errors.Wrap(err, "parse host:port")
		mainlog.Error(err)
		return nil
	}
	l := mainlog.With("host", host)

	if ip := net.ParseIP(host); ip != nil {
		l.With("ip", ip).Info()
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return ip
	}
	l.Info("returning nil")
	return nil
}

var zeros = make([]byte, 1456)

type fakeReader struct {
	N int
}

func (r *fakeReader) Close() error {
	return nil
}

func (r *fakeReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	if len(p) > r.N {
		p = p[:r.N]
	}

	for len(p) > 0 {
		n = copy(p, zeros)
		r.N -= n
		p = p[n:]
	}

	if r.N == 0 {
		err = io.EOF
	}
	return
}

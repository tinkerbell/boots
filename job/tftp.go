package job

import (
	tftpgo "github.com/betawaffle/tftp-go"
	"github.com/tinkerbell/boots/tftp"
)

func (j Job) ServeTFTP(filename, client string) (tftpgo.ReadCloser, error) {
	return tftp.Open(j.mac, filename, client)
}

package simulator

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

type tcpWrapper struct {
	tpm *tcp.TPM
	bytes.Buffer
}

func (w *tcpWrapper) Write(p []byte) (int, error) {
	resp, err := w.tpm.Send(p)
	if err != nil {
		return 0, err
	}
	w.Buffer.Reset()
	w.Buffer.Write(resp)
	return len(p), nil
}

func (w *tcpWrapper) Close() error {
	return w.tpm.Close()
}

func Get() (io.ReadWriteCloser, error) {
	// 1. Read command.port and platform.port dynamically based on source file location
	cmdAddr := "localhost:2321"
	platAddr := "localhost:2322"

	if _, filename, _, ok := runtime.Caller(0); ok {
		portDir := filepath.Join(filepath.Dir(filename), "..")
		if data, err := os.ReadFile(filepath.Join(portDir, "command.port")); err == nil {
			cmdAddr = "localhost:" + strings.TrimSpace(string(data))
		}
		if data, err := os.ReadFile(filepath.Join(portDir, "platform.port")); err == nil {
			platAddr = "localhost:" + strings.TrimSpace(string(data))
		}
	}

	// 2. Open TCP transport
	tpm, err := tcp.Open(tcp.Config{
		CommandAddress:  cmdAddr,
		PlatformAddress: platAddr,
	})
	if err != nil {
		return nil, err
	}

	// 3. Power Cycle / Reset
	_ = tpm.PowerOff()
	if err := tpm.PowerOn(); err != nil {
		tpm.Close()
		return nil, err
	}

	// 4. Send Startup command (TPM2_Startup with TPMSUClear)
	if _, err := (tpm2.Startup{StartupType: tpm2.TPMSUClear}).Execute(tpm); err != nil {
		tpm.Close()
		return nil, err
	}

	return &tcpWrapper{tpm: tpm}, nil
}

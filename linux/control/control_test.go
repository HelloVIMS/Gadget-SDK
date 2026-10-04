//go:build linux

package control

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
)

type fakeDevice struct {
	paired   string
	unpaired bool
	sent     []string
}

func (f *fakeDevice) Status() gadget.Status {
	return gadget.Status{State: gadget.StateConnected, ID: "gaaaaaaaaaaaaaaaa", Host: "vimsbox"}
}

func (f *fakeDevice) Pair(_ context.Context, uri string) (gadget.PairResult, error) {
	if !strings.HasPrefix(uri, protocol.PairingScheme) {
		return gadget.PairResult{}, errors.New("not a pairing URI")
	}
	f.paired = uri
	return gadget.PairResult{ID: "gaaaaaaaaaaaaaaaa", Host: "vimsbox", SAS: "123 456"}, nil
}

func (f *fakeDevice) Unpair() error { f.unpaired = true; return nil }

func (f *fakeDevice) SendMessage(_ context.Context, text, thread string) (protocol.MessageOutput, error) {
	f.sent = append(f.sent, thread+"|"+text)
	return protocol.MessageOutput{ID: "m-9"}, nil
}

func serve(t *testing.T, path string, dev Device) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, dev, Info{Name: "pi", Key: "k"}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestControlOps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	dev := &fakeDevice{}
	serve(t, path, dev)
	ctx := context.Background()

	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v %v", st.Mode().Perm(), err)
	}
	resp, err := Do(ctx, path, Request{Op: OpStatus})
	if err != nil || resp.Status.State != gadget.StateConnected || resp.Info.Name != "pi" {
		t.Fatalf("status: %+v %v", resp, err)
	}
	resp, err = Do(ctx, path, Request{Op: OpPair, URI: protocol.PairingScheme + "x"})
	if err != nil || resp.Pair.SAS != "123 456" || dev.paired == "" {
		t.Fatalf("pair: %+v %v", resp, err)
	}
	if _, err := Do(ctx, path, Request{Op: OpPair, URI: "nope"}); err == nil || !strings.Contains(err.Error(), "not a pairing URI") {
		t.Fatalf("bad pair: %v", err)
	}
	long := strings.Repeat("é", 3000)
	resp, err = Do(ctx, path, Request{Op: OpSend, Text: long, Thread: "t1"})
	if err != nil || resp.Message.ID != "m-9" || dev.sent[0] != "t1|"+long {
		t.Fatalf("send: %+v %v", resp, err)
	}
	if _, err := Do(ctx, path, Request{Op: OpUnpair}); err != nil || !dev.unpaired {
		t.Fatalf("unpair: %v", err)
	}
	if _, err := Do(ctx, path, Request{Op: "reboot"}); err == nil {
		t.Fatal("unknown op accepted")
	}
	if _, err := Do(ctx, path, Request{Op: OpSend, Text: strings.Repeat("x", maxRequest)}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized request: %v", err)
	}
}

func TestControlReplacesStaleSocketAndRefusesSecondAgent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// Leave the file behind without a listener, as a crash would.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	serve(t, path, &fakeDevice{})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Serve(ctx, path, &fakeDevice{}, Info{}); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("second agent: %v", err)
	}
}

func TestDoWithoutService(t *testing.T) {
	_, err := Do(context.Background(), filepath.Join(t.TempDir(), "none.sock"), Request{Op: OpStatus})
	if err == nil || !strings.Contains(err.Error(), "is it running") {
		t.Fatalf("got %v", err)
	}
}

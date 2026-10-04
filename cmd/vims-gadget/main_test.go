//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCLI builds the agent, runs it as the service would, and drives it
// through the control socket the way a user does.
func TestCLI(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "vims-gadget")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	state, socket := filepath.Join(dir, "state"), filepath.Join(dir, "control.sock")
	svc := exec.Command(bin, "run", "--state-dir", state, "--socket", socket, "--name", "CLI test")
	var logs strings.Builder
	svc.Stdout, svc.Stderr = &logs, &logs
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		svc.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- svc.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("service exit: %v\n%s", err, logs.String())
			}
		case <-time.After(10 * time.Second):
			svc.Process.Kill()
			t.Errorf("service did not stop on SIGTERM\n%s", logs.String())
		}
	})
	cli := func(args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Env = append(os.Environ(), "VIMS_GADGET_SOCKET="+socket)
		out, err := c.CombinedOutput()
		return string(out), err
	}
	var out string
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if out, err = cli("status"); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("status: %v\n%s\nservice log:\n%s", err, out, logs.String())
	}
	if !strings.Contains(out, "state:    unpaired") || !strings.Contains(out, "name:     CLI test") {
		t.Fatalf("status output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(state, "device.key")); err != nil {
		t.Fatalf("key not created: %v", err)
	}
	if out, err := cli("send-user-msg", "hello"); err == nil || !strings.Contains(out, "not connected") {
		t.Fatalf("send while unpaired: %v %s", err, out)
	}
	if out, err := cli("pair", "vimsgadget1:bad"); err == nil || !strings.Contains(out, "pairing URI") {
		t.Fatalf("bad pair: %v %s", err, out)
	}
	if out, err := cli("bogus"); err == nil || !strings.Contains(out, "unknown command") {
		t.Fatalf("unknown command: %v %s", err, out)
	}
	if out, err := cli("version"); err != nil || !strings.HasPrefix(out, "vims-gadget ") {
		t.Fatalf("version: %v %s", err, out)
	}
}

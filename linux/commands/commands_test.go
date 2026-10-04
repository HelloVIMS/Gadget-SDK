//go:build linux

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
)

func command(t *testing.T, home, name string) gadget.Command {
	t.Helper()
	for _, c := range All(Options{Agent: "vims-gadget test", Home: home}) {
		if c.Name == name {
			info := protocol.CommandInfo{Name: c.Name, Description: c.Description, Risk: c.Risk, Input: c.Input}
			if err := info.Validate(); err != nil {
				t.Fatalf("%s descriptor: %v", name, err)
			}
			return c
		}
	}
	t.Fatalf("no command %s", name)
	return gadget.Command{}
}

func call(t *testing.T, c gadget.Command, input any, body []byte) (*gadget.Response, error) {
	t.Helper()
	b, _ := json.Marshal(input)
	return c.Handler(context.Background(), &gadget.Request{Command: c.Name, Input: b, Body: body})
}

func output[T any](t *testing.T, r *gadget.Response) T {
	t.Helper()
	var v T
	b, _ := json.Marshal(r.Output)
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCommandSetIsComplete(t *testing.T) {
	cmds := All(Options{})
	risks := map[string]protocol.Risk{}
	for _, c := range cmds {
		risks[c.Name] = c.Risk
	}
	want := map[string]protocol.Risk{"system.run": protocol.RiskExec, "file.read": protocol.RiskRead, "file.write": protocol.RiskWrite, "device.health": protocol.RiskRead}
	for name, risk := range want {
		if risks[name] != risk {
			t.Errorf("%s risk %q, want %q", name, risks[name], risk)
		}
	}
	if len(cmds) != len(want) {
		t.Errorf("%d commands, want %d", len(cmds), len(want))
	}
}

func TestSystemRun(t *testing.T) {
	home := t.TempDir()
	run := command(t, home, "system.run")

	r, err := call(t, run, map[string]any{"command": `echo out; echo err >&2; pwd; exit 3`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	o := output[runOutput](t, r)
	if o.ExitCode != 3 || o.Stdout != "out\n"+home+"\n" || o.Stderr != "err\n" || o.TimedOut {
		t.Fatalf("got %+v", o)
	}

	sub := filepath.Join(home, "sub")
	os.Mkdir(sub, 0o755)
	r, err = call(t, run, map[string]any{"command": "pwd; cat", "cwd": "sub", "stdin": "fed in"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o := output[runOutput](t, r); o.Stdout != sub+"\nfed in" || o.ExitCode != 0 {
		t.Fatalf("cwd/stdin: %+v", o)
	}

	start := time.Now()
	r, err = call(t, run, map[string]any{"command": "sleep 30 & sleep 30; echo never", "timeout_ms": 300}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o := output[runOutput](t, r); !o.TimedOut || o.ExitCode != -1 || strings.Contains(o.Stdout, "never") {
		t.Fatalf("timeout: %+v", o)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout took %v: the process group was not killed", time.Since(start))
	}

	r, err = call(t, run, map[string]any{"command": "head -c 600000 /dev/zero | tr '\\0' a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o := output[runOutput](t, r); !o.Truncated || len(o.Stdout) != maxStreamCapture {
		t.Fatalf("truncation: truncated=%v len=%d", o.Truncated, len(o.Stdout))
	}

	for _, in := range []map[string]any{{}, {"command": "  "}, {"command": "true", "cwd": "missing-dir"}, {"command": "true", "bogus": 1}} {
		if _, err := call(t, run, in, nil); !protocol.IsCode(err, protocol.CodeInvalidInput) {
			t.Errorf("%v: %v", in, err)
		}
	}
}

func TestSystemRunHonoursCancellation(t *testing.T) {
	run := command(t, t.TempDir(), "system.run")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := run.Handler(ctx, &gadget.Request{Command: run.Name, Input: json.RawMessage(`{"command":"sleep 30"}`)})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("cancel: %v after %v", err, time.Since(start))
	}
}

func TestFileReadChunks(t *testing.T) {
	home := t.TempDir()
	read := command(t, home, "file.read")
	data := bytes.Repeat([]byte("0123456789"), 10_000) // 100 KB
	os.WriteFile(filepath.Join(home, "big.txt"), data, 0o640)

	var got []byte
	offset := int64(0)
	for i := 0; ; i++ {
		r, err := call(t, read, map[string]any{"path": "~/big.txt", "offset": offset}, nil)
		if err != nil {
			t.Fatal(err)
		}
		o := output[readOutput](t, r)
		if o.Size != int64(len(data)) || o.Mode != "0640" || o.Path != filepath.Join(home, "big.txt") {
			t.Fatalf("chunk %d: %+v", i, o)
		}
		got = append(got, r.Body...)
		offset += int64(o.Length)
		if o.EOF {
			break
		}
		if i > 3 {
			t.Fatal("never reached eof")
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatal("chunks do not reassemble the file")
	}

	r, err := call(t, read, map[string]any{"path": "big.txt", "offset": 5, "length": 3}, nil)
	if err != nil || string(r.Body) != "567" {
		t.Fatalf("ranged read: %q %v", r.Body, err)
	}
	if _, err := call(t, read, map[string]any{"path": home}, nil); !protocol.IsCode(err, protocol.CodeInvalidInput) {
		t.Fatalf("directory: %v", err)
	}
	if _, err := call(t, read, map[string]any{"path": "missing"}, nil); !protocol.IsCode(err, protocol.CodeInvalidInput) {
		t.Fatalf("missing: %v", err)
	}
	os.WriteFile(filepath.Join(home, "secret"), []byte("x"), 0o000)
	if os.Geteuid() != 0 {
		if _, err := call(t, read, map[string]any{"path": "secret"}, nil); !protocol.IsCode(err, protocol.CodeDenied) {
			t.Fatalf("unreadable: %v", err)
		}
	}
}

func TestFileWriteSingleAndChunked(t *testing.T) {
	home := t.TempDir()
	write := command(t, home, "file.write")
	target := filepath.Join(home, "notes", "todo.txt")

	if _, err := call(t, write, map[string]any{"path": "notes/todo.txt", "content": "milk"}, nil); !protocol.IsCode(err, protocol.CodeInvalidInput) {
		t.Fatalf("missing parent without mkdir: %v", err)
	}
	r, err := call(t, write, map[string]any{"path": "notes/todo.txt", "content": "milk\n", "mkdir": true, "mode": "0600"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o := output[writeOutput](t, r); !o.Complete || o.Size != 5 {
		t.Fatalf("single write: %+v", o)
	}
	if b, _ := os.ReadFile(target); string(b) != "milk\n" {
		t.Fatalf("content %q", b)
	}
	if st, _ := os.Stat(target); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}

	// Overwrite with a body keeps the existing mode.
	if _, err := call(t, write, map[string]any{"path": target}, []byte("eggs\n")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(target); st.Mode().Perm() != 0o600 {
		t.Fatalf("overwrite changed mode to %v", st.Mode().Perm())
	}

	// Chunked: the old content stays until the final chunk lands.
	f := false
	parts := [][]byte{bytes.Repeat([]byte("a"), 1000), bytes.Repeat([]byte("b"), 1000), []byte("c")}
	offset := 0
	for i, p := range parts {
		in := map[string]any{"path": target, "upload_id": "up-1", "offset": offset}
		if i < len(parts)-1 {
			in["final"] = f
		}
		r, err := call(t, write, in, p)
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		offset += len(p)
		o := output[writeOutput](t, r)
		if o.Complete != (i == len(parts)-1) || o.Size != int64(offset) {
			t.Fatalf("chunk %d: %+v", i, o)
		}
		if i < len(parts)-1 {
			if b, _ := os.ReadFile(target); string(b) != "eggs\n" {
				t.Fatalf("target replaced before the upload completed: %q", b)
			}
		}
	}
	if b, _ := os.ReadFile(target); len(b) != 2001 || b[2000] != 'c' {
		t.Fatalf("assembled %d bytes", len(b))
	}

	if _, err := call(t, write, map[string]any{"path": target, "upload_id": "up-2", "offset": 10}, []byte("x")); !protocol.IsCode(err, protocol.CodeInvalidInput) {
		t.Fatalf("offset without a started upload: %v", err)
	}
	if _, err := call(t, write, map[string]any{"path": target, "upload_id": "up-3", "final": false}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, write, map[string]any{"path": target, "upload_id": "up-3", "offset": 5}, []byte("x")); !protocol.IsCode(err, protocol.CodeInvalidInput) {
		t.Fatalf("out-of-order chunk: %v", err)
	}
	for _, in := range []map[string]any{
		{"path": target, "final": false},
		{"path": target, "offset": 3},
		{"path": target, "upload_id": "bad id"},
		{"path": target, "mode": "4755"},
		{"path": target, "mode": "rw"},
		{"path": home},
	} {
		if _, err := call(t, write, in, []byte("x")); !protocol.IsCode(err, protocol.CodeInvalidInput) {
			t.Errorf("%v: %v", in, err)
		}
	}
	if _, err := call(t, write, map[string]any{"path": target, "content": "x"}, []byte("y")); !protocol.IsCode(err, protocol.CodeInvalidInput) {
		t.Fatalf("content and body: %v", err)
	}
	if _, err := call(t, write, map[string]any{"path": target}, make([]byte, maxWriteChunk+1)); !protocol.IsCode(err, protocol.CodeTooLarge) {
		t.Fatalf("oversized chunk: %v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(home, "notes", ".todo.txt.vims-gadget-*"))
	if len(leftovers) != 1 { // up-3 is still open
		t.Fatalf("temp files: %v", leftovers)
	}
}

func TestHealthReadsTheMachine(t *testing.T) {
	root := t.TempDir()
	must := func(p, s string) {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("etc/os-release", "NAME=Debian\nPRETTY_NAME=\"Raspberry Pi OS (bookworm)\"\n")
	must("proc/uptime", "12345.67 9999.00\n")
	must("proc/loadavg", "0.50 0.25 0.10 1/123 4567\n")
	must("proc/meminfo", "MemTotal:        8000000 kB\nMemFree:  100 kB\nMemAvailable:    6000000 kB\n")
	must("sys/class/thermal/thermal_zone0/type", "cpu-thermal\n")
	must("sys/class/thermal/thermal_zone0/temp", "48250\n")
	must("sys/class/thermal/thermal_zone1/type", "battery\n")
	must("sys/class/thermal/thermal_zone1/temp", "60000\n")

	h := readHealth(root, Options{Agent: "vims-gadget test", Home: root})
	if h.OS != "Raspberry Pi OS (bookworm)" || h.UptimeS != 12345 || h.Load != [3]float64{0.5, 0.25, 0.1} {
		t.Fatalf("health %+v", h)
	}
	if h.Memory.TotalBytes != 8000000*1024 || h.Memory.AvailableBytes != 6000000*1024 {
		t.Fatalf("memory %+v", h.Memory)
	}
	if h.TemperatureC == nil || *h.TemperatureC != 48.25 {
		t.Fatalf("temperature %v (the CPU zone must win over hotter non-CPU zones)", h.TemperatureC)
	}
	if len(h.Disks) == 0 || h.Disks[0].Path != "/" || h.Disks[0].TotalBytes == 0 || h.Kernel == "" || h.Agent != "vims-gadget test" {
		t.Fatalf("disks/kernel %+v", h)
	}

	live, err := call(t, command(t, t.TempDir(), "device.health"), map[string]any{}, nil)
	if err != nil || output[health](t, live).Hostname == "" {
		t.Fatalf("live health: %v", err)
	}
}

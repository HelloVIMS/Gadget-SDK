//go:build linux

// Package security is the Linux agent's security reporting: what it runs
// (security.attest: the agent binary's hash, OS, kernel, boot, listening
// ports) and what it sees (security.report: new listening programs and
// failed logins to this machine).
package security

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hellovims/gadget-sdk/protocol"
)

// Attestation describes this machine and the running agent.
func Attestation(version string) (protocol.SecurityAttestation, error) {
	exe, err := os.Executable()
	if err != nil {
		return protocol.SecurityAttestation{}, err
	}
	sum, err := fileSHA256(exe)
	if err != nil {
		return protocol.SecurityAttestation{}, err
	}
	ports, _ := Listening()
	return protocol.SecurityAttestation{
		Firmware: sum, Version: clip(version, 200), OS: clip(osPretty(), 200),
		Kernel: clip(readTrim("/proc/sys/kernel/osrelease"), 200), BootID: clip(readTrim("/proc/sys/kernel/random/boot_id"), 200),
		Listening: ports,
	}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

func osPretty() string {
	b, _ := os.ReadFile("/etc/os-release")
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "Linux"
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// socket is one listening TCP socket from /proc/net/tcp{,6}.
type socket struct {
	port     int
	loopback bool
}

func listening() ([]socket, error) {
	var out []socket
	var firstErr error
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(p)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, parseProcNet(b)...)
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// parseProcNet reads LISTEN (state 0A) sockets.
func parseProcNet(b []byte) []socket {
	var out []socket
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		addr, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			continue
		}
		loop := addr == "0100007F" || addr == "00000000000000000000000001000000"
		out = append(out, socket{port: int(port), loopback: loop})
	}
	return out
}

// Listening is the sorted tcp/<port> list of listening ports.
func Listening() ([]string, error) {
	socks, err := listening()
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	var ports []int
	for _, s := range socks {
		if !seen[s.port] {
			seen[s.port] = true
			ports = append(ports, s.port)
		}
	}
	sort.Ints(ports)
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		if len(out) < 256 {
			out = append(out, "tcp/"+strconv.Itoa(p))
		}
	}
	return out, nil
}

// Watcher reports new listeners and failed logins.
type Watcher struct {
	Report func(context.Context, protocol.SecurityReport) error
	Every  time.Duration
	// Journal reads sshd's journal since a time; nil uses journalctl.
	Journal func(ctx context.Context, since time.Time) ([]byte, error)
}

var failedLogin = regexp.MustCompile(`(?:Failed (?:password|publickey) for (?:invalid user )?(\S+)|Invalid user (\S*)) from (\S+) port`)

// Run watches until ctx ends. The first pass only learns what is normal.
func (w *Watcher) Run(ctx context.Context) {
	every := w.Every
	if every <= 0 {
		every = 30 * time.Second
	}
	journal := w.Journal
	if journal == nil {
		journal = func(ctx context.Context, since time.Time) ([]byte, error) {
			return exec.CommandContext(ctx, "journalctl", "--no-pager", "-q", "-o", "cat", "--since", since.Format("2006-01-02 15:04:05"), "_COMM=sshd").Output()
		}
	}
	known := map[int]bool{}
	first := true
	since := time.Now()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		now := time.Now()
		if socks, err := listening(); err == nil {
			for _, s := range socks {
				if known[s.port] {
					continue
				}
				known[s.port] = true
				if first {
					continue
				}
				sev, where := "low", "this machine only"
				if !s.loopback {
					sev, where = "medium", "reachable from the network"
				}
				w.send(ctx, protocol.SecurityReport{Kind: "new_listener", Severity: sev,
					Summary: fmt.Sprintf("something started listening on port %d (%s)", s.port, where), Data: map[string]any{"port": s.port}})
			}
		}
		if out, err := journal(ctx, since); err == nil {
			for ip, n := range CountFailures(out) {
				sev := "low"
				if n.count >= 5 {
					sev = "high"
				}
				w.send(ctx, protocol.SecurityReport{Kind: "login_failed", Severity: sev, Source: ip,
					Summary: fmt.Sprintf("%d failed SSH logins from %s (last as %q)", n.count, ip, clip(n.user, 64)), Data: map[string]any{"failures": n.count}})
			}
		}
		first, since = false, now
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *Watcher) send(ctx context.Context, r protocol.SecurityReport) {
	if w.Report == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_ = w.Report(cctx, r)
}

type failures struct {
	count int
	user  string
}

// CountFailures counts failed SSH logins per source address in sshd output.
func CountFailures(out []byte) map[string]failures {
	m := map[string]failures{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		g := failedLogin.FindStringSubmatch(sc.Text())
		if g == nil {
			continue
		}
		user := g[1]
		if user == "" {
			user = g[2]
		}
		f := m[g[3]]
		f.count++
		f.user = user
		m[g[3]] = f
	}
	return m
}

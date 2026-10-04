//go:build linux

package commands

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/hellovims/gadget-sdk/gadget"
)

type memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

type disk struct {
	Path       string `json:"path"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

type health struct {
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	Kernel       string     `json:"kernel"`
	Arch         string     `json:"arch"`
	UptimeS      int64      `json:"uptime_s"`
	Load         [3]float64 `json:"load"`
	Memory       memory     `json:"memory"`
	Disks        []disk     `json:"disks"`
	TemperatureC *float64   `json:"temperature_c,omitempty"`
	Agent        string     `json:"agent"`
}

func healthCommand(opts Options) func(context.Context, *gadget.Request) (*gadget.Response, error) {
	return func(_ context.Context, req *gadget.Request) (*gadget.Response, error) {
		if err := req.Decode(&struct{}{}); err != nil {
			return nil, err
		}
		return &gadget.Response{Output: readHealth("/", opts)}, nil
	}
}

// readHealth gathers what is available; a missing source leaves its field
// zero rather than failing the whole report.
func readHealth(root string, opts Options) health {
	h := health{Arch: runtime.GOARCH, Agent: opts.Agent, OS: osName(filepath.Join(root, "etc/os-release"))}
	h.Hostname, _ = os.Hostname()
	var uts unix.Utsname
	if unix.Uname(&uts) == nil {
		h.Kernel = unix.ByteSliceToString(uts.Release[:])
	}
	if b, err := os.ReadFile(filepath.Join(root, "proc/uptime")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				h.UptimeS = int64(v)
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "proc/loadavg")); err == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			h.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	h.Memory = readMemInfo(filepath.Join(root, "proc/meminfo"))
	seen := map[uint64]bool{}
	for _, p := range []string{"/", opts.Home} {
		var st unix.Statfs_t
		if p == "" || unix.Statfs(p, &st) != nil {
			continue
		}
		var dev unix.Stat_t
		if unix.Stat(p, &dev) == nil {
			if seen[dev.Dev] {
				continue
			}
			seen[dev.Dev] = true
		}
		bs := uint64(st.Bsize)
		h.Disks = append(h.Disks, disk{Path: p, TotalBytes: st.Blocks * bs, FreeBytes: st.Bavail * bs})
	}
	h.TemperatureC = cpuTemperature(filepath.Join(root, "sys/class/thermal"))
	return h
}

func osName(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "Linux"
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return "Linux"
}

func readMemInfo(path string) memory {
	var m memory
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			m.TotalBytes = kb * 1024
		case "MemAvailable:":
			m.AvailableBytes = kb * 1024
		}
	}
	return m
}

// cpuTemperature is the hottest CPU-ish thermal zone, or any zone when none
// is labelled as the CPU.
func cpuTemperature(dir string) *float64 {
	zones, _ := filepath.Glob(filepath.Join(dir, "thermal_zone*"))
	var best, other *float64
	for _, z := range zones {
		raw, err := os.ReadFile(filepath.Join(z, "temp"))
		if err != nil {
			continue
		}
		milli, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if err != nil || milli <= -273000 {
			continue
		}
		c := milli / 1000
		typ, _ := os.ReadFile(filepath.Join(z, "type"))
		t := strings.ToLower(string(typ))
		if strings.Contains(t, "cpu") || strings.Contains(t, "soc") || strings.Contains(t, "pkg") {
			if best == nil || c > *best {
				best = &c
			}
		} else if other == nil || c > *other {
			other = &c
		}
	}
	if best != nil {
		return best
	}
	return other
}

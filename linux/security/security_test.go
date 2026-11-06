//go:build linux

package security

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hellovims/gadget-sdk/protocol"
)

func TestParseProcNet(t *testing.T) {
	in := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0000000000000000 20 4 0 10 -1
`
	got := parseProcNet([]byte(in))
	if len(got) != 2 || got[0] != (socket{port: 8080, loopback: true}) || got[1] != (socket{port: 22}) {
		t.Fatalf("%+v", got)
	}
}

func TestAttestationIsValid(t *testing.T) {
	a, err := Attestation("vims-gadget test")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("%+v: %v", a, err)
	}
}

func TestWatcherReportsFailedLogins(t *testing.T) {
	var mu sync.Mutex
	var got []protocol.SecurityReport
	ctx, cancel := context.WithCancel(context.Background())
	w := &Watcher{Every: 10 * time.Millisecond,
		Report: func(_ context.Context, r protocol.SecurityReport) error {
			mu.Lock()
			got = append(got, r)
			mu.Unlock()
			if err := r.Validate(); err != nil {
				t.Errorf("invalid report %+v: %v", r, err)
			}
			cancel()
			return nil
		},
		Journal: func(context.Context, time.Time) ([]byte, error) {
			return []byte(strings.Repeat("Failed password for root from 192.0.2.5 port 4000 ssh2\n", 6)), nil
		}}
	w.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 || got[0].Kind != "login_failed" || got[0].Severity != "high" || got[0].Source != "192.0.2.5" {
		t.Fatalf("%+v", got)
	}
}

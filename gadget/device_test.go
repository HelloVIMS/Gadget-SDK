package gadget

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hellovims/gadget-sdk/protocol"
	"github.com/hellovims/gadget-sdk/protocol/wscarrier"
)

// testHost is a minimal VGP host: pairing tickets, known keys, sessions and
// message.send. The VIMS daemon is the real host.
type testHost struct {
	t   *testing.T
	key protocol.KeyPair
	srv *httptest.Server

	mu       sync.Mutex
	tickets  map[[32]byte]time.Time
	known    map[protocol.Key]protocol.Hello
	sessions map[string]*protocol.Session
	sas      map[string]string
	messages []protocol.MessageInput
	resumes  int
}

func newTestHost(t *testing.T) *testHost {
	t.Helper()
	kp, err := protocol.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &testHost{t: t, key: kp, tickets: map[[32]byte]time.Time{}, known: map[protocol.Key]protocol.Hello{}, sessions: map[string]*protocol.Session{}, sas: map[string]string{}}
	h.srv = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(func() {
		h.mu.Lock()
		for _, s := range h.sessions {
			s.Close(protocol.CloseShutdown, "test over")
		}
		h.mu.Unlock()
		h.srv.Close()
	})
	return h
}

func (h *testHost) addr() string { return strings.TrimPrefix(h.srv.URL, "http://") }

func (h *testHost) pairingURI(addrs ...string) string {
	h.t.Helper()
	tok, _ := protocol.NewToken(nil)
	h.mu.Lock()
	h.tickets[sha256.Sum256(tok[:])] = time.Now().Add(time.Minute)
	h.mu.Unlock()
	if len(addrs) == 0 {
		addrs = []string{h.addr()}
	}
	uri, err := protocol.Pairing{HostKey: h.key.Public, Addrs: addrs, Token: tok, Expires: time.Now().Add(time.Minute), HostName: "testhost"}.URI()
	if err != nil {
		h.t.Fatal(err)
	}
	return uri
}

func (h *testHost) decide(remote protocol.Key, ch protocol.ClientHello) protocol.ServerHello {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := protocol.DeviceID(remote)
	switch ch.Mode {
	case protocol.ModeResume:
		if _, ok := h.known[remote]; !ok {
			return protocol.Refuse(protocol.RefuseUnpaired, "unknown gadget")
		}
		h.resumes++
		return protocol.Accept(id, "testhost")
	case protocol.ModePair:
		tok, err := protocol.ParseToken(ch.Token)
		if err != nil {
			return protocol.Refuse(protocol.RefuseTokenInvalid, "bad token")
		}
		sum := sha256.Sum256(tok[:])
		for k, exp := range h.tickets {
			if subtle.ConstantTimeCompare(k[:], sum[:]) == 1 {
				delete(h.tickets, k)
				if time.Now().After(exp) {
					return protocol.Refuse(protocol.RefuseTokenExpired, "expired")
				}
				h.known[remote] = protocol.Hello{}
				return protocol.Accept(id, "testhost")
			}
		}
		return protocol.Refuse(protocol.RefuseTokenInvalid, "unknown token")
	}
	return protocol.Refuse(protocol.RefuseVersion, "mode")
}

func (h *testHost) serve(w http.ResponseWriter, r *http.Request) {
	c, err := wscarrier.Upgrade(w, r)
	if err != nil {
		return
	}
	conn, _, err := protocol.ServerHandshake(c, h.key, 5*time.Second, h.decide)
	if err != nil {
		c.Close()
		return
	}
	hello, err := conn.ReadHello(5 * time.Second)
	if err != nil {
		conn.Close()
		return
	}
	id := protocol.DeviceID(conn.RemoteKey())
	if err := conn.SendWelcome(protocol.Welcome{ID: id, Host: "testhost", Time: time.Now().Unix(), Addrs: []string{h.addr()}, Services: []string{protocol.ServiceMessageSend}, Limits: protocol.DefaultLimits}); err != nil {
		conn.Close()
		return
	}
	s := protocol.NewSession(conn, protocol.SessionConfig{Handler: h, IdleTimeout: 75 * time.Second})
	h.mu.Lock()
	h.known[conn.RemoteKey()] = hello
	if old := h.sessions[id]; old != nil {
		old.Close(protocol.CloseReplaced, "newer session")
	}
	h.sessions[id] = s
	h.sas[id] = conn.SAS()
	h.mu.Unlock()
	_ = s.Run()
	h.mu.Lock()
	if h.sessions[id] == s {
		delete(h.sessions, id)
	}
	h.mu.Unlock()
}

func (h *testHost) HandleCall(ctx context.Context, c *protocol.Call) (*protocol.Reply, error) {
	if c.Command != protocol.ServiceMessageSend {
		return nil, protocol.Errorf(protocol.CodeUnknownCommand, "%s", c.Command)
	}
	var in protocol.MessageInput
	if err := json.Unmarshal(c.Input, &in); err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "%v", err)
	}
	h.mu.Lock()
	h.messages = append(h.messages, in)
	h.mu.Unlock()
	out, _ := json.Marshal(protocol.MessageOutput{ID: "m-1", At: time.Now().UTC().Format(time.RFC3339)})
	return &protocol.Reply{Output: out}, nil
}

func (h *testHost) HandleEvent(*protocol.Event) {}

func (h *testHost) session(id string) *protocol.Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[id]
}

func (h *testHost) forget(key protocol.Key) {
	h.mu.Lock()
	delete(h.known, key)
	h.mu.Unlock()
}

type device struct {
	*Device
	store  *FileStore
	states chan Status
	cancel context.CancelFunc
	done   chan error
}

func startDevice(t *testing.T, dir string) *device {
	t.Helper()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	states := make(chan Status, 64)
	dev, err := New(Config{
		Name:  "Test Lamp",
		Model: "unit test",
		Commands: []Command{{
			Name:        "light.set",
			Description: "Sets the light",
			Risk:        protocol.RiskWrite,
			Handler: func(ctx context.Context, req *Request) (*Response, error) {
				var in struct {
					RGB string `json:"rgb"`
				}
				if err := req.Decode(&in); err != nil {
					return nil, err
				}
				return &Response{Output: map[string]string{"rgb": in.RGB}}, nil
			},
		}},
		Store:    store,
		OnStatus: func(s Status) { states <- s },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &device{Device: dev, store: store, states: states, cancel: cancel, done: make(chan error, 1)}
	go func() { d.done <- dev.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-d.done
	})
	d.waitState(t, StateUnpaired, StateConnecting)
	return d
}

func (d *device) waitState(t *testing.T, want ...State) Status {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case s := <-d.states:
			for _, w := range want {
				if s.State == w {
					return s
				}
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %v; status %+v", want, d.Status())
		}
	}
}

func TestPairInvokeMessageAndReconnect(t *testing.T) {
	host := newTestHost(t)
	dev := startDevice(t, t.TempDir())
	ctx := context.Background()

	res, err := dev.Pair(ctx, host.pairingURI())
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != dev.ID() || res.Host != "testhost" {
		t.Fatalf("pair result %+v", res)
	}
	dev.waitState(t, StateConnected)
	host.mu.Lock()
	hostSAS := host.sas[dev.ID()]
	hello := host.known[dev.PublicKey()]
	host.mu.Unlock()
	if hostSAS != res.SAS {
		t.Fatalf("SAS mismatch: gadget %s host %s", res.SAS, hostSAS)
	}
	if hello.Name != "Test Lamp" || len(hello.Commands) != 1 || hello.Commands[0].Risk != protocol.RiskWrite {
		t.Fatalf("host saw HELLO %+v", hello)
	}
	p, err := dev.store.Pairing()
	if err != nil || p == nil || p.DeviceID != dev.ID() || p.HostKey != host.key.Public.String() || p.Addrs[0] != host.addr() {
		t.Fatalf("stored pairing %+v %v", p, err)
	}

	r, err := host.session(dev.ID()).Call(ctx, "light.set", map[string]string{"rgb": "00ff00"}, nil)
	if err != nil || string(r.Output) != `{"rgb":"00ff00"}` {
		t.Fatalf("light.set: %v %s", err, r.Output)
	}
	if _, err := host.session(dev.ID()).Call(ctx, "light.set", map[string]any{"rgb": "x", "extra": 1}, nil); !protocol.IsCode(err, protocol.CodeInvalidInput) {
		t.Fatalf("unknown input field: %v", err)
	}
	if _, err := host.session(dev.ID()).Call(ctx, "missing.cmd", nil, nil); !protocol.IsCode(err, protocol.CodeUnknownCommand) {
		t.Fatalf("missing command: %v", err)
	}

	out, err := dev.SendMessage(ctx, "garage door open", "garage")
	if err != nil || out.ID != "m-1" {
		t.Fatalf("send: %+v %v", out, err)
	}
	host.mu.Lock()
	got := host.messages
	host.mu.Unlock()
	if len(got) != 1 || got[0].Text != "garage door open" || got[0].Thread != "garage" {
		t.Fatalf("host got %+v", got)
	}
	if _, err := dev.SendMessage(ctx, "", ""); !protocol.IsCode(err, protocol.CodeInvalidInput) {
		t.Fatalf("empty message: %v", err)
	}

	// The network drops: the gadget resumes on its own.
	host.session(dev.ID()).Conn().Close()
	dev.waitState(t, StateConnecting, StateReconnecting)
	dev.waitState(t, StateConnected)
	host.mu.Lock()
	resumes := host.resumes
	host.mu.Unlock()
	if resumes != 1 {
		t.Fatalf("resumes = %d", resumes)
	}
}

func TestRevokedGadgetForgetsPairing(t *testing.T) {
	host := newTestHost(t)
	dev := startDevice(t, t.TempDir())
	if _, err := dev.Pair(context.Background(), host.pairingURI()); err != nil {
		t.Fatal(err)
	}
	dev.waitState(t, StateConnected)
	host.forget(dev.PublicKey())
	host.session(dev.ID()).Close(protocol.CloseRevoked, "removed by owner")
	dev.waitState(t, StateUnpaired)
	if p, err := dev.store.Pairing(); err != nil || p != nil {
		t.Fatalf("pairing kept after revocation: %+v %v", p, err)
	}
	// Pairing again works with a fresh ticket.
	if _, err := dev.Pair(context.Background(), host.pairingURI()); err != nil {
		t.Fatal(err)
	}
	dev.waitState(t, StateConnected)
}

func TestHostThatForgotGadgetUnpairsOnResume(t *testing.T) {
	host := newTestHost(t)
	dir := t.TempDir()
	dev := startDevice(t, dir)
	if _, err := dev.Pair(context.Background(), host.pairingURI()); err != nil {
		t.Fatal(err)
	}
	dev.waitState(t, StateConnected)
	host.forget(dev.PublicKey())
	host.session(dev.ID()).Conn().Close()
	dev.waitState(t, StateUnpaired)
	if p, _ := dev.store.Pairing(); p != nil {
		t.Fatalf("pairing kept: %+v", p)
	}
}

func TestPairFailures(t *testing.T) {
	host := newTestHost(t)
	dev := startDevice(t, t.TempDir())
	ctx := context.Background()

	uri := host.pairingURI()
	if _, err := dev.Pair(ctx, uri); err != nil {
		t.Fatal(err)
	}
	dev.waitState(t, StateConnected)
	var he *protocol.HandshakeError
	if _, err := dev.Pair(ctx, uri); !errors.As(err, &he) || he.Code != protocol.RefuseTokenInvalid {
		t.Fatalf("reused token: %v", err)
	}
	// A failed re-pair keeps the existing pairing, and the gadget resumes.
	dev.waitState(t, StateConnected)
	if p, _ := dev.store.Pairing(); p == nil {
		t.Fatal("failed re-pair dropped the pairing")
	}

	expired, _ := protocol.Pairing{HostKey: host.key.Public, Addrs: []string{host.addr()}, Expires: time.Now().Add(-time.Minute)}.URI()
	if _, err := dev.Pair(ctx, expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired URI: %v", err)
	}
	if _, err := dev.Pair(ctx, "not-a-uri"); err == nil {
		t.Fatal("garbage URI accepted")
	}
}

func TestPairFallsBackAcrossAddresses(t *testing.T) {
	host := newTestHost(t)
	dead := closedAddr(t)
	dev := startDevice(t, t.TempDir())
	res, err := dev.Pair(context.Background(), host.pairingURI(dead, host.addr()))
	if err != nil {
		t.Fatal(err)
	}
	if res.Addr != host.addr() {
		t.Fatalf("connected via %s", res.Addr)
	}
	p, _ := dev.store.Pairing()
	if p.Addrs[0] != host.addr() {
		t.Fatalf("working address not stored first: %v", p.Addrs)
	}
}

func TestPairRequiresRun(t *testing.T) {
	store, _ := NewFileStore(t.TempDir())
	dev, err := New(Config{Name: "idle", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	host := newTestHost(t)
	if _, err := dev.Pair(context.Background(), host.pairingURI()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("got %v", err)
	}
	if _, err := dev.SendMessage(context.Background(), "hi", ""); !errors.Is(err, ErrOffline) {
		t.Fatalf("got %v", err)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	store, _ := NewFileStore(t.TempDir())
	h := func(context.Context, *Request) (*Response, error) { return nil, nil }
	bad := []Config{
		{Name: "", Store: store},
		{Name: "x"},
		{Name: "x", Store: store, Commands: []Command{{Name: "Bad Name", Handler: h}}},
		{Name: "x", Store: store, Commands: []Command{{Name: "a.b", Handler: h}, {Name: "a.b", Handler: h}}},
		{Name: "x", Store: store, Commands: []Command{{Name: "a.b"}}},
		{Name: "x", Store: store, Limits: protocol.Limits{MaxChunk: 10, MaxMessage: 10, MaxCalls: 1}},
	}
	for i, c := range bad {
		if _, err := New(c); err == nil {
			t.Errorf("config %d accepted", i)
		}
	}
	dev, err := New(Config{Name: "ok", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := New(Config{Name: "ok", Store: store})
	if dev.ID() != again.ID() || !protocol.ValidDeviceID(dev.ID()) {
		t.Fatal("the key is not persisted across restarts")
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s.Pairing(); p != nil || err != nil {
		t.Fatalf("fresh store has pairing %+v %v", p, err)
	}
	kp, _ := protocol.GenerateKeyPair(nil)
	want := &Pairing{DeviceID: protocol.DeviceID(kp.Public), HostKey: kp.Public.String(), HostName: "h", Addrs: []string{"10.0.0.1:8189"}, PairedAt: time.Now().UTC().Truncate(time.Second)}
	if err := s.SavePairing(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Pairing()
	if err != nil || got.DeviceID != want.DeviceID || got.HostKey != want.HostKey || !got.PairedAt.Equal(want.PairedAt) {
		t.Fatalf("round trip %+v %v", got, err)
	}
	if err := s.SavePairing(&Pairing{DeviceID: "nope"}); err == nil {
		t.Fatal("invalid pairing saved")
	}
	if err := s.ClearPairing(); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearPairing(); err != nil {
		t.Fatalf("clearing twice: %v", err)
	}
}

func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

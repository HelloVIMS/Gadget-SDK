package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hellovims/gadget-sdk/protocol/memcarrier"
)

var _ Carrier = (*memcarrier.End)(nil)

type pair struct {
	gadget, host           *Conn
	hello                  Hello
	welcome                Welcome
	gadgetKey, hostKey     KeyPair
	gadgetSAS, hostSAS     string
	gadgetCarrier, hostEnd *memcarrier.End
}

func testHello(l Limits) Hello {
	return Hello{
		Name:     "Test Gadget",
		Model:    "unit test",
		Platform: "test/none",
		Commands: []CommandInfo{
			{Name: "echo", Risk: RiskRead, Input: json.RawMessage(`{"type":"object"}`)},
			{Name: "slow", Risk: RiskExec},
		},
		Limits: l,
	}
}

// establish runs a full handshake and HELLO/WELCOME over a memory pipe.
func establish(t *testing.T, gadgetLimits, hostLimits Limits) *pair {
	t.Helper()
	a, b := memcarrier.Pipe()
	p := &pair{gadgetKey: mustKeyPair(t), hostKey: mustKeyPair(t), gadgetCarrier: a, hostEnd: b}
	type result struct {
		c   *Conn
		h   Hello
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, _, err := ServerHandshake(b, p.hostKey, 5*time.Second, func(remote Key, hello ClientHello) ServerHello {
			return Accept(DeviceID(remote), "testhost")
		})
		if err != nil {
			done <- result{err: err}
			return
		}
		h, err := c.ReadHello(5 * time.Second)
		if err != nil {
			done <- result{err: err}
			return
		}
		err = c.SendWelcome(Welcome{ID: DeviceID(c.RemoteKey()), Host: "testhost", Time: time.Now().Unix(), Addrs: []string{"127.0.0.1:8189"}, Services: []string{ServiceMessageSend}, Limits: hostLimits})
		done <- result{c, h, err}
	}()
	gc, sh, err := ClientHandshake(a, p.gadgetKey, p.hostKey.Public, ClientHello{Mode: ModeResume}, 5*time.Second)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if sh.ID != DeviceID(p.gadgetKey.Public) || sh.Host != "testhost" {
		t.Fatalf("server hello %+v", sh)
	}
	w, err := gc.ExchangeHello(testHello(gadgetLimits), 5*time.Second)
	if err != nil {
		t.Fatalf("exchange hello: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("host side: %v", r.err)
	}
	p.gadget, p.host, p.hello, p.welcome = gc, r.c, r.h, w
	p.gadgetSAS, p.hostSAS = gc.SAS(), r.c.SAS()
	return p
}

func TestHandshakeAuthenticatesBothSides(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	if p.gadgetSAS != p.hostSAS {
		t.Fatalf("SAS differs: gadget %s host %s", p.gadgetSAS, p.hostSAS)
	}
	if !bytes.Equal(p.gadget.HandshakeHash(), p.host.HandshakeHash()) {
		t.Fatal("handshake hashes differ")
	}
	if p.host.RemoteKey() != p.gadgetKey.Public || p.gadget.RemoteKey() != p.hostKey.Public {
		t.Fatal("remote keys wrong")
	}
	if p.hello.Name != "Test Gadget" || len(p.hello.Commands) != 2 || p.welcome.ID != DeviceID(p.gadgetKey.Public) {
		t.Fatalf("hello %+v welcome %+v", p.hello, p.welcome)
	}
}

func TestHandshakeRefusalReachesGadget(t *testing.T) {
	a, b := memcarrier.Pipe()
	host, gadget := mustKeyPair(t), mustKeyPair(t)
	var seen ClientHello
	go func() {
		_, _, err := ServerHandshake(b, host, 5*time.Second, func(remote Key, hello ClientHello) ServerHello {
			seen = hello
			return Refuse(RefuseTokenExpired, "ticket expired")
		})
		var he *HandshakeError
		if !errors.As(err, &he) || he.Code != RefuseTokenExpired {
			t.Errorf("server returned %v", err)
		}
		b.Close()
	}()
	tok, _ := NewToken(nil)
	_, sh, err := ClientHandshake(a, gadget, host.Public, ClientHello{Mode: ModePair, Token: tok.String()}, 5*time.Second)
	var he *HandshakeError
	if !errors.As(err, &he) || he.Code != RefuseTokenExpired || sh.OK {
		t.Fatalf("client got %v %+v", err, sh)
	}
	if seen.Mode != ModePair || seen.Token != tok.String() {
		t.Fatalf("server saw %+v", seen)
	}
}

func TestHandshakeFailsAgainstWrongHostKey(t *testing.T) {
	a, b := memcarrier.Pipe()
	host, impostor, gadget := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	errc := make(chan error, 1)
	go func() {
		_, _, err := ServerHandshake(b, impostor, 5*time.Second, func(Key, ClientHello) ServerHello {
			t.Error("impostor decided on a hello it should not have decrypted")
			return Accept("g", "")
		})
		b.Close()
		errc <- err
	}()
	_, _, err := ClientHandshake(a, gadget, host.Public, ClientHello{Mode: ModeResume}, 2*time.Second)
	if err == nil {
		t.Fatal("gadget completed a handshake with a host whose key it did not pin")
	}
	var pe *ProtocolError
	if serr := <-errc; !errors.As(serr, &pe) {
		t.Fatalf("impostor got %v, want a protocol error", serr)
	}
}

func TestHandshakeRejectsUnknownMode(t *testing.T) {
	a, b := memcarrier.Pipe()
	host, gadget := mustKeyPair(t), mustKeyPair(t)
	go func() {
		_, _, _ = ServerHandshake(b, host, 5*time.Second, func(Key, ClientHello) ServerHello {
			t.Error("decide called for an unknown mode")
			return Accept("g", "")
		})
		b.Close()
	}()
	_, _, err := ClientHandshake(a, gadget, host.Public, ClientHello{Mode: "steal"}, 2*time.Second)
	var he *HandshakeError
	if !errors.As(err, &he) || he.Code != RefuseVersion {
		t.Fatalf("got %v", err)
	}
}

func TestChunkingReassemblesLargeFrames(t *testing.T) {
	small := Limits{MaxChunk: MinChunk, MaxMessage: 1 << 20, MaxCalls: 4}
	p := establish(t, small, small)
	body := make([]byte, 200_000)
	rand.Read(body)
	go func() {
		f, _ := NewFrame(FrameEvent, 0, EventHeader{Name: "blob"}, body)
		if err := p.host.WriteFrame(f); err != nil {
			t.Error(err)
		}
	}()
	got, err := p.gadget.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != FrameEvent || !bytes.Equal(got.Body, body) {
		t.Fatalf("reassembled %s with %d bytes", got.Type, len(got.Body))
	}
}

func TestWriteFrameRespectsPeerMaxMessage(t *testing.T) {
	p := establish(t, Limits{MaxChunk: MinChunk, MaxMessage: MinMessage, MaxCalls: 1}, DefaultLimits)
	f, _ := NewFrame(FrameEvent, 0, EventHeader{Name: "big"}, make([]byte, MinMessage))
	if err := p.host.WriteFrame(f); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameRejectsOversizedChunk(t *testing.T) {
	p := establish(t, Limits{MaxChunk: MinChunk, MaxMessage: MinMessage, MaxCalls: 1}, DefaultLimits)
	// Bypass the host's own limit to send a chunk bigger than the gadget's max_chunk.
	p.host.setPeer(DefaultLimits)
	f, _ := NewFrame(FrameEvent, 0, EventHeader{Name: "x"}, make([]byte, 4000))
	go p.host.WriteFrame(f)
	_, err := p.gadget.ReadFrame()
	var pe *ProtocolError
	if !errors.As(err, &pe) || !strings.Contains(err.Error(), "max_chunk") {
		t.Fatalf("got %v", err)
	}
}

func TestTamperedTransportMessageIsFatal(t *testing.T) {
	a, b := memcarrier.Pipe()
	tamper := &tamperCarrier{Carrier: b}
	host, gadget := mustKeyPair(t), mustKeyPair(t)
	go func() {
		c, _, err := ServerHandshake(tamper, host, 5*time.Second, func(r Key, _ ClientHello) ServerHello { return Accept(DeviceID(r), "h") })
		if err != nil {
			t.Error(err)
			return
		}
		c.setPeer(DefaultLimits)
		tamper.flip.Store(true)
		f, _ := NewFrame(FrameEvent, 0, EventHeader{Name: "x"}, nil)
		_ = c.WriteFrame(f)
	}()
	gc, _, err := ClientHandshake(a, gadget, host.Public, ClientHello{Mode: ModeResume}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	gc.setLocal(DefaultLimits)
	if _, err := gc.ReadFrame(); err == nil || !strings.Contains(err.Error(), "authenticate") {
		t.Fatalf("tampered message read as %v", err)
	}
}

type tamperCarrier struct {
	Carrier
	flip atomic.Bool
}

func (c *tamperCarrier) WriteMessage(p []byte) error {
	if c.flip.Load() {
		p = append([]byte(nil), p...)
		p[len(p)-1] ^= 0x80
	}
	return c.Carrier.WriteMessage(p)
}

// handlerFuncs adapts closures to Handler.
type handlerFuncs struct {
	call  func(ctx context.Context, c *Call) (*Reply, error)
	event func(ev *Event)
}

func (h handlerFuncs) HandleCall(ctx context.Context, c *Call) (*Reply, error) {
	if h.call == nil {
		return nil, Errorf(CodeUnknownCommand, "%s", c.Command)
	}
	return h.call(ctx, c)
}

func (h handlerFuncs) HandleEvent(ev *Event) {
	if h.event != nil {
		h.event(ev)
	}
}

type sessions struct {
	gadget, host *Session
	gadgetErr    chan error
	hostErr      chan error
}

func startSessions(t *testing.T, p *pair, gadgetH, hostH Handler, gcfg, hcfg SessionConfig) *sessions {
	t.Helper()
	gcfg.Handler, gcfg.Initiator = gadgetH, true
	hcfg.Handler, hcfg.Initiator = hostH, false
	s := &sessions{
		gadget:    NewSession(p.gadget, gcfg),
		host:      NewSession(p.host, hcfg),
		gadgetErr: make(chan error, 1),
		hostErr:   make(chan error, 1),
	}
	go func() { s.gadgetErr <- s.gadget.Run() }()
	go func() { s.hostErr <- s.host.Run() }()
	t.Cleanup(func() {
		s.gadget.Close(CloseShutdown, "test over")
		s.host.Close(CloseShutdown, "test over")
	})
	return s
}

func echoHandler() Handler {
	return handlerFuncs{call: func(ctx context.Context, c *Call) (*Reply, error) {
		switch c.Command {
		case "echo":
			return &Reply{Output: c.Input, Body: c.Body}, nil
		case "slow":
			<-ctx.Done()
			return nil, ctx.Err()
		case "fail":
			return nil, Errorf(CodeDenied, "no thanks")
		case "boom":
			panic("kaboom")
		case "plain":
			return nil, errors.New("disk on fire")
		}
		return nil, Errorf(CodeUnknownCommand, "unknown command %q", c.Command)
	}}
}

func TestSessionCallsBothWays(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	var msgs atomic.Int32
	hostH := handlerFuncs{call: func(ctx context.Context, c *Call) (*Reply, error) {
		if c.Command != ServiceMessageSend {
			return nil, Errorf(CodeUnknownCommand, "%s", c.Command)
		}
		if c.ID%2 != 1 {
			t.Errorf("gadget call id %d is not odd", c.ID)
		}
		var in MessageInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, Errorf(CodeInvalidInput, "%v", err)
		}
		msgs.Add(1)
		out, _ := json.Marshal(MessageOutput{ID: "m-1", At: time.Now().UTC().Format(time.RFC3339)})
		return &Reply{Output: out}, nil
	}}
	s := startSessions(t, p, echoHandler(), hostH, SessionConfig{}, SessionConfig{})
	ctx := context.Background()

	r, err := s.host.Call(ctx, "echo", map[string]any{"x": 1}, []byte("body"))
	if err != nil || string(r.Output) != `{"x":1}` || string(r.Body) != "body" {
		t.Fatalf("echo: %+v %v", r, err)
	}
	r, err = s.gadget.Call(ctx, ServiceMessageSend, MessageInput{Text: "garage door open"}, nil)
	if err != nil || msgs.Load() != 1 {
		t.Fatalf("message.send: %v", err)
	}
	var mo MessageOutput
	if err := r.DecodeOutput(&mo); err != nil || mo.ID != "m-1" {
		t.Fatalf("output %+v %v", mo, err)
	}

	for cmd, code := range map[string]string{"fail": CodeDenied, "missing": CodeUnknownCommand, "boom": CodeFailed, "plain": CodeFailed} {
		_, err := s.host.Call(ctx, cmd, nil, nil)
		if !IsCode(err, code) {
			t.Errorf("%s: got %v, want %s", cmd, err, code)
		}
	}
	if _, err := s.host.Call(ctx, "Not Valid", nil, nil); err == nil {
		t.Error("invalid command name was sent")
	}
}

func TestSessionCancelAndTimeout(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	var canceled atomic.Int32
	gadgetH := handlerFuncs{call: func(ctx context.Context, c *Call) (*Reply, error) {
		<-ctx.Done()
		canceled.Add(1)
		return nil, ctx.Err()
	}}
	s := startSessions(t, p, gadgetH, nil, SessionConfig{}, SessionConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.host.Call(ctx, "slow", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("call did not honour its deadline")
	}
	waitFor(t, func() bool { return canceled.Load() == 1 }, "gadget handler to see the cancellation")

	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel2() }()
	if _, err := s.host.Call(ctx2, "slow", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	waitFor(t, func() bool { return canceled.Load() == 2 }, "CANCEL to reach the gadget")
}

func TestSessionBusyBeyondMaxCalls(t *testing.T) {
	p := establish(t, Limits{MaxChunk: MaxTransportMessage, MaxMessage: 1 << 20, MaxCalls: 1}, DefaultLimits)
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	gadgetH := handlerFuncs{call: func(ctx context.Context, c *Call) (*Reply, error) {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return &Reply{}, nil
	}}
	s := startSessions(t, p, gadgetH, nil, SessionConfig{}, SessionConfig{})
	// The host's own semaphore follows the gadget's max_calls, so drive the
	// second call below it to check the gadget enforces the limit itself.
	first := make(chan error, 1)
	go func() { _, err := s.host.Call(context.Background(), "hold", nil, nil); first <- err }()
	<-started
	f, _ := NewFrame(FrameCall, 1000, CallHeader{Command: "hold"}, nil)
	ch := make(chan Frame, 1)
	s.host.mu.Lock()
	s.host.pending[1000] = ch
	s.host.mu.Unlock()
	if err := p.host.WriteFrame(f); err != nil {
		t.Fatal(err)
	}
	var rh ResultHeader
	if err := (<-ch).DecodeHeader(&rh); err != nil || rh.OK || rh.Error.Code != CodeBusy {
		t.Fatalf("second call got %+v %v", rh, err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestSessionEventsAndClose(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	got := make(chan *Event, 1)
	hostH := handlerFuncs{event: func(ev *Event) { got <- ev }}
	s := startSessions(t, p, nil, hostH, SessionConfig{}, SessionConfig{})
	if err := s.gadget.Notify("button", map[string]string{"button": "boot", "action": "press"}, []byte{1}); err != nil {
		t.Fatal(err)
	}
	ev := <-got
	if ev.Name != "button" || string(ev.Data) != `{"action":"press","button":"boot"}` || !bytes.Equal(ev.Body, []byte{1}) {
		t.Fatalf("event %+v", ev)
	}
	s.host.Close(CloseRevoked, "removed by owner")
	err := <-s.gadgetErr
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseRevoked || ce.Message != "removed by owner" {
		t.Fatalf("gadget ended with %v", err)
	}
	if err := <-s.hostErr; !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("host ended with %v", err)
	}
	if _, err := s.gadget.Call(context.Background(), "echo", nil, nil); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("call after close: %v", err)
	}
}

func TestSessionKeepaliveAndIdleTimeout(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	s := startSessions(t, p, nil, nil,
		SessionConfig{PingInterval: 100 * time.Millisecond, IdleTimeout: 400 * time.Millisecond},
		SessionConfig{IdleTimeout: 400 * time.Millisecond})
	// Pings in both directions keep both sides alive well past IdleTimeout.
	time.Sleep(1200 * time.Millisecond)
	if s.gadget.Err() != nil || s.host.Err() != nil {
		t.Fatalf("sessions died despite keepalive: gadget %v host %v", s.gadget.Err(), s.host.Err())
	}

	q := establish(t, DefaultLimits, DefaultLimits)
	silent := startSessions(t, q, nil, nil, SessionConfig{}, SessionConfig{IdleTimeout: 200 * time.Millisecond})
	select {
	case err := <-silent.hostErr:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("idle host ended with %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle session was not closed")
	}
}

func TestSessionRejectsHelloMidSession(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	s := startSessions(t, p, nil, nil, SessionConfig{}, SessionConfig{})
	f, _ := NewFrame(FrameHello, 0, testHello(DefaultLimits), nil)
	if err := p.gadget.WriteFrame(f); err != nil {
		t.Fatal(err)
	}
	var pe *ProtocolError
	if err := <-s.hostErr; !errors.As(err, &pe) {
		t.Fatalf("host ended with %v", err)
	}
	var ce *CloseError
	if err := <-s.gadgetErr; !errors.As(err, &ce) || ce.Code != CloseProtocolError {
		t.Fatalf("gadget ended with %v", err)
	}
}

func TestSessionRejectsWrongParity(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	s := startSessions(t, p, nil, echoHandler(), SessionConfig{}, SessionConfig{})
	f, _ := NewFrame(FrameCall, 2, CallHeader{Command: "echo"}, nil) // gadget must use odd ids
	if err := p.gadget.WriteFrame(f); err != nil {
		t.Fatal(err)
	}
	var pe *ProtocolError
	if err := <-s.hostErr; !errors.As(err, &pe) {
		t.Fatalf("host ended with %v", err)
	}
}

func TestConcurrentCallsAndLargeBodies(t *testing.T) {
	p := establish(t, Limits{MaxChunk: 4096, MaxMessage: 4 << 20, MaxCalls: 8}, Limits{MaxChunk: 4096, MaxMessage: 4 << 20, MaxCalls: 8})
	s := startSessions(t, p, echoHandler(), nil, SessionConfig{}, SessionConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := bytes.Repeat([]byte{byte(i)}, 50_000+i)
			r, err := s.host.Call(context.Background(), "echo", map[string]int{"i": i}, body)
			if err != nil {
				t.Errorf("call %d: %v", i, err)
				return
			}
			if string(r.Output) != fmt.Sprintf(`{"i":%d}`, i) || !bytes.Equal(r.Body, body) {
				t.Errorf("call %d: wrong reply", i)
			}
		}(i)
	}
	wg.Wait()
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

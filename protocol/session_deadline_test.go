package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionDoesNotSendAlreadyCanceledCalls(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	var calls atomic.Int32
	h := handlerFuncs{call: func(ctx context.Context, c *Call) (*Reply, error) {
		if c.Command == "echo" {
			calls.Add(1)
		}
		return &Reply{}, nil
	}}
	s := startSessions(t, p, h, nil, SessionConfig{}, SessionConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 128; i++ {
		if _, err := s.host.Call(ctx, "echo", nil, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled call returned %v", err)
		}
	}
	// A round trip drains the preceding CALL frames; wait for their handlers too.
	barrier, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if _, err := s.host.Call(barrier, "barrier", nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		s.gadget.mu.Lock()
		defer s.gadget.mu.Unlock()
		return len(s.gadget.running) == 0
	}, "handlers to finish")
	if got := calls.Load(); got != 0 {
		t.Fatalf("executed %d already-canceled calls", got)
	}
}

type signaledInput struct{ marshaled chan struct{} }

func (in signaledInput) MarshalJSON() ([]byte, error) {
	close(in.marshaled)
	return []byte(`{}`), nil
}
func TestSessionTimeoutExcludesTimeWaitingForCapacity(t *testing.T) {
	limits := DefaultLimits
	limits.MaxCalls = 1
	p := establish(t, limits, DefaultLimits)
	observed := make(chan time.Time, 1)
	h := handlerFuncs{call: func(ctx context.Context, c *Call) (*Reply, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("missing deadline")
		}
		observed <- deadline
		return &Reply{}, nil
	}}
	s := startSessions(t, p, h, nil, SessionConfig{}, SessionConfig{})
	// Reserve the peer's only slot without starting a call.
	s.host.outSem <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	input := signaledInput{marshaled: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := s.host.Call(ctx, "echo", input, nil); done <- err }()
	<-input.marshaled
	time.Sleep(200 * time.Millisecond)
	<-s.host.outSem
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	remote := <-observed
	if remote.After(deadline.Add(100 * time.Millisecond)) {
		t.Fatalf("queueing extended remote deadline by %v", remote.Sub(deadline))
	}
}
func TestSessionLargeTimeoutDoesNotOverflow(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	observed := make(chan time.Duration, 1)
	h := handlerFuncs{call: func(ctx context.Context, c *Call) (*Reply, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			observed <- 0
		} else {
			observed <- time.Until(deadline)
		}
		return &Reply{}, nil
	}}
	startSessions(t, p, h, nil, SessionConfig{}, SessionConfig{})
	f, err := NewFrame(FrameCall, 1000, CallHeader{Command: "echo", TimeoutMS: math.MaxInt64}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.host.WriteFrame(f); err != nil {
		t.Fatal(err)
	}
	select {
	case remaining := <-observed:
		if remaining < 24*time.Hour {
			t.Fatalf("large timeout overflowed to %v", remaining)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not start")
	}
}
func TestSessionCancellationDuringInputEncoding(t *testing.T) {
	p := establish(t, DefaultLimits, DefaultLimits)
	s := startSessions(t, p, echoHandler(), nil, SessionConfig{}, SessionConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := s.host.Call(ctx, "echo", cancelingInput{cancel}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if got := s.host.nextID.Load(); got != 0 {
		t.Fatalf("allocated an id for a canceled call: %d", got)
	}
}

type cancelingInput struct{ cancel context.CancelFunc }

func (in cancelingInput) MarshalJSON() ([]byte, error) { in.cancel(); return json.Marshal(struct{}{}) }

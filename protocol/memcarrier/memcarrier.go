// Package memcarrier is an in-memory carrier pair (it satisfies
// protocol.Carrier), for tests and simulators that run a gadget and a host
// in one process.
package memcarrier

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// MaxMessage is the VGP transport message limit (protocol.MaxTransportMessage).
const MaxMessage = 65535

// ErrClosed is returned after either end closed the pipe.
var ErrClosed = errors.New("memcarrier: closed")

type pipe struct {
	once   sync.Once
	closed chan struct{}
}

// End is one end of a pipe.
type End struct {
	p      *pipe
	in     <-chan []byte
	out    chan<- []byte
	remote string
	mu     sync.Mutex
	rdl    time.Time
	wdl    time.Time
	wakeup chan struct{}
}

// Pipe returns two connected ends. Each direction buffers up to 64
// messages; a writer blocks beyond that until the reader catches up.
func Pipe() (*End, *End) {
	p := &pipe{closed: make(chan struct{})}
	ab, ba := make(chan []byte, 64), make(chan []byte, 64)
	a := &End{p: p, in: ba, out: ab, remote: "mem:b", wakeup: make(chan struct{}, 1)}
	b := &End{p: p, in: ab, out: ba, remote: "mem:a", wakeup: make(chan struct{}, 1)}
	return a, b
}

func (e *End) deadline(write bool) (<-chan time.Time, func()) {
	e.mu.Lock()
	t := e.rdl
	if write {
		t = e.wdl
	}
	e.mu.Unlock()
	if t.IsZero() {
		return nil, func() {}
	}
	d := time.Until(t)
	if d <= 0 {
		c := make(chan time.Time, 1)
		c <- t
		return c, func() {}
	}
	timer := time.NewTimer(d)
	return timer.C, func() { timer.Stop() }
}

// ReadMessage returns the next message.
func (e *End) ReadMessage() ([]byte, error) {
	for {
		dl, stop := e.deadline(false)
		select {
		case m := <-e.in:
			stop()
			return m, nil
		case <-e.p.closed:
			stop()
			select {
			case m := <-e.in:
				return m, nil
			default:
			}
			return nil, ErrClosed
		case <-dl:
			return nil, fmt.Errorf("memcarrier: read: %w", os.ErrDeadlineExceeded)
		case <-e.wakeup:
			stop()
		}
	}
}

// WriteMessage sends a copy of p.
func (e *End) WriteMessage(p []byte) error {
	if len(p) > MaxMessage {
		return fmt.Errorf("memcarrier: message of %d bytes exceeds %d", len(p), MaxMessage)
	}
	m := append([]byte(nil), p...)
	dl, stop := e.deadline(true)
	defer stop()
	select {
	case <-e.p.closed:
		return ErrClosed
	default:
	}
	select {
	case e.out <- m:
		return nil
	case <-e.p.closed:
		return ErrClosed
	case <-dl:
		return fmt.Errorf("memcarrier: write: %w", os.ErrDeadlineExceeded)
	}
}

// SetReadDeadline bounds reads; a blocked read re-arms with the new value.
func (e *End) SetReadDeadline(t time.Time) error {
	e.mu.Lock()
	e.rdl = t
	e.mu.Unlock()
	select {
	case e.wakeup <- struct{}{}:
	default:
	}
	return nil
}

// SetWriteDeadline bounds writes.
func (e *End) SetWriteDeadline(t time.Time) error {
	e.mu.Lock()
	e.wdl = t
	e.mu.Unlock()
	return nil
}

// Close closes both ends.
func (e *End) Close() error {
	e.p.once.Do(func() { close(e.p.closed) })
	return nil
}

// RemoteAddr names the other end.
func (e *End) RemoteAddr() string { return e.remote }

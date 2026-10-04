package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Call is an inbound CALL.
type Call struct {
	ID      uint32
	Command string
	Input   json.RawMessage
	Body    []byte
}

// Reply is a call's successful outcome.
type Reply struct {
	Output json.RawMessage
	Body   []byte
}

// DecodeOutput unmarshals the reply's output into v.
func (r *Reply) DecodeOutput(v any) error {
	if len(r.Output) == 0 {
		return errors.New("vgp: reply has no output")
	}
	return json.Unmarshal(r.Output, v)
}

// Event is an inbound EVENT.
type Event struct {
	Name string
	Data json.RawMessage
	Body []byte
}

// Handler serves a session's inbound calls and events. HandleCall runs on
// its own goroutine per call and should honour ctx; returning a
// *RemoteError chooses the code the caller sees. HandleEvent runs on the
// read loop, in order, and must not block.
type Handler interface {
	HandleCall(ctx context.Context, call *Call) (*Reply, error)
	HandleEvent(ev *Event)
}

// SessionConfig configures a Session.
type SessionConfig struct {
	Handler Handler
	// Initiator is true on the gadget: its calls use odd ids.
	Initiator bool
	// PingInterval sends a PING after this long without sending; 0 never.
	PingInterval time.Duration
	// IdleTimeout ends the session after this long without receiving; 0 never.
	IdleTimeout time.Duration
}

// Session multiplexes calls, results, events and keepalive over a Conn.
type Session struct {
	conn *Conn
	cfg  SessionConfig

	nextID   atomic.Uint32
	lastSend atomic.Int64
	outSem   chan struct{}

	mu      sync.Mutex
	pending map[uint32]chan Frame
	running map[uint32]context.CancelFunc

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	err    error
}

// NewSession starts nothing; call Run.
func NewSession(conn *Conn, cfg SessionConfig) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		conn:    conn,
		cfg:     cfg,
		outSem:  make(chan struct{}, max(conn.PeerLimits().MaxCalls, 1)),
		pending: map[uint32]chan Frame{},
		running: map[uint32]context.CancelFunc{},
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	s.lastSend.Store(time.Now().UnixNano())
	return s
}

// Conn is the session's connection.
func (s *Session) Conn() *Conn { return s.conn }

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is why the session ended: a *CloseError when the peer closed, a
// *ProtocolError, a carrier error, or ErrSessionClosed after Close.
func (s *Session) Err() error {
	select {
	case <-s.done:
		return s.err
	default:
		return nil
	}
}

// Run reads until the session ends and returns why (see Err).
func (s *Session) Run() error {
	if s.cfg.PingInterval > 0 {
		go s.keepalive()
	}
	for {
		if s.cfg.IdleTimeout > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}
		f, err := s.conn.ReadFrame()
		if err == nil {
			err = s.dispatch(f)
		}
		if err != nil {
			var pe *ProtocolError
			if errors.As(err, &pe) {
				s.conn.SendClose(CloseProtocolError, pe.msg)
			}
			s.finish(err)
			return s.err
		}
		select {
		case <-s.done:
			return s.err
		default:
		}
	}
}

func (s *Session) dispatch(f Frame) error {
	switch f.Type {
	case FrameCall:
		return s.handleCall(f)
	case FrameResult:
		s.mu.Lock()
		ch := s.pending[f.ID]
		delete(s.pending, f.ID)
		s.mu.Unlock()
		if ch != nil {
			ch <- f
		}
	case FrameCancel:
		s.mu.Lock()
		cancel := s.running[f.ID]
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	case FrameEvent:
		var h EventHeader
		if err := f.DecodeHeader(&h); err != nil {
			return err
		}
		if s.cfg.Handler != nil && h.Name != "" {
			s.cfg.Handler.HandleEvent(&Event{Name: h.Name, Data: h.Data, Body: f.Body})
		}
	case FramePing:
		go s.write(Frame{Type: FramePong, ID: f.ID})
	case FramePong:
	case FrameClose:
		ce := &CloseError{}
		_ = f.DecodeHeader(ce)
		if ce.Code == "" {
			ce.Code = CloseShutdown
		}
		s.finish(ce)
	default:
		return protocolErrorf("unexpected %s during a session", f.Type)
	}
	return nil
}

func (s *Session) peerParityOK(id uint32) bool {
	if id == 0 {
		return false
	}
	// The peer of an initiator is the host: even ids; and vice versa.
	return (id%2 == 1) != s.cfg.Initiator
}

func (s *Session) handleCall(f Frame) error {
	if !s.peerParityOK(f.ID) {
		return protocolErrorf("CALL id %d has the wrong parity", f.ID)
	}
	var h CallHeader
	if err := f.DecodeHeader(&h); err != nil {
		go s.reply(f.ID, nil, Errorf(CodeInvalidInput, "unreadable CALL header"))
		return nil
	}
	s.mu.Lock()
	if _, dup := s.running[f.ID]; dup {
		s.mu.Unlock()
		return protocolErrorf("CALL id %d reused", f.ID)
	}
	if len(s.running) >= s.conn.LocalLimits().MaxCalls {
		s.mu.Unlock()
		go s.reply(f.ID, nil, Errorf(CodeBusy, "already running %d calls", len(s.running)))
		return nil
	}
	ctx, cancel := context.WithCancel(s.ctx)
	if h.TimeoutMS > 0 {
		ctx, cancel = context.WithTimeout(s.ctx, time.Duration(h.TimeoutMS)*time.Millisecond)
	}
	s.running[f.ID] = cancel
	s.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.running, f.ID)
			s.mu.Unlock()
		}()
		if s.cfg.Handler == nil || !ValidCommandName(h.Command) {
			s.reply(f.ID, nil, Errorf(CodeUnknownCommand, "unknown command %q", h.Command))
			return
		}
		reply, err := s.serve(ctx, &Call{ID: f.ID, Command: h.Command, Input: h.Input, Body: f.Body})
		s.reply(f.ID, reply, err)
	}()
	return nil
}

func (s *Session) serve(ctx context.Context, call *Call) (reply *Reply, err error) {
	defer func() {
		if p := recover(); p != nil {
			reply, err = nil, Errorf(CodeFailed, "%s panicked: %v", call.Command, p)
		}
	}()
	return s.cfg.Handler.HandleCall(ctx, call)
}

func (s *Session) reply(id uint32, r *Reply, err error) {
	h := ResultHeader{OK: err == nil}
	var body []byte
	if err != nil {
		var re *RemoteError
		switch {
		case errors.As(err, &re):
			h.Error = re
		case errors.Is(err, context.Canceled):
			h.Error = &RemoteError{Code: CodeCanceled}
		case errors.Is(err, context.DeadlineExceeded):
			h.Error = &RemoteError{Code: CodeTimeout}
		default:
			h.Error = &RemoteError{Code: CodeFailed, Message: err.Error()}
		}
	} else if r != nil {
		h.Output, body = r.Output, r.Body
	}
	f, ferr := NewFrame(FrameResult, id, h, body)
	if ferr == nil && f.Size() > s.conn.PeerLimits().MaxMessage {
		f, ferr = NewFrame(FrameResult, id, ResultHeader{Error: Errorf(CodeTooLarge, "result of %d bytes exceeds the caller's max_message", f.Size())}, nil)
	}
	if ferr != nil {
		f, _ = NewFrame(FrameResult, id, ResultHeader{Error: Errorf(CodeFailed, "unencodable result: %v", ferr)}, nil)
	}
	_ = s.write(f)
}

// write sends f; a carrier failure ends the session.
func (s *Session) write(f Frame) error {
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}
	err := s.conn.WriteFrame(f)
	switch {
	case err == nil:
		s.lastSend.Store(time.Now().UnixNano())
	case errors.Is(err, ErrFrameTooLarge):
	default:
		s.finish(err)
		_ = s.conn.Close()
	}
	return err
}

func (s *Session) keepalive() {
	tick := time.NewTicker(max(s.cfg.PingInterval/5, 50*time.Millisecond))
	defer tick.Stop()
	var seq uint32
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			if time.Since(time.Unix(0, s.lastSend.Load())) >= s.cfg.PingInterval {
				seq++
				_ = s.write(Frame{Type: FramePing, ID: seq})
			}
		}
	}
}

// newID allocates the next call id: odd on the initiator, even on the
// responder, never 0.
func (s *Session) newID() uint32 {
	for {
		id := s.nextID.Add(1) * 2
		if s.cfg.Initiator {
			id--
		}
		if id != 0 {
			return id
		}
	}
}

// Call invokes a command (on a gadget) or a service (on the host) and waits
// for its result. input is marshalled as JSON (json.RawMessage passes
// through; nil omits it). ctx's deadline becomes the call's timeout_ms. A
// failure reported by the peer is a *RemoteError.
func (s *Session) Call(ctx context.Context, command string, input any, body []byte) (*Reply, error) {
	if !ValidCommandName(command) {
		return nil, fmt.Errorf("vgp: invalid command name %q", command)
	}
	h := CallHeader{Command: command}
	switch v := input.(type) {
	case nil:
	case json.RawMessage:
		h.Input = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("vgp: encode input: %w", err)
		}
		h.Input = b
	}
	if dl, ok := ctx.Deadline(); ok {
		h.TimeoutMS = max(time.Until(dl).Milliseconds(), 1)
	}
	select {
	case s.outSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrSessionClosed
	}
	defer func() { <-s.outSem }()

	id := s.newID()
	ch := make(chan Frame, 1)
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, ErrSessionClosed
	default:
	}
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()

	f, err := NewFrame(FrameCall, id, h, body)
	if err != nil {
		return nil, err
	}
	if err := s.write(f); err != nil {
		if errors.Is(err, ErrFrameTooLarge) {
			return nil, Errorf(CodeTooLarge, "%v", err)
		}
		return nil, ErrSessionClosed
	}
	select {
	case r := <-ch:
		var rh ResultHeader
		if err := r.DecodeHeader(&rh); err != nil {
			return nil, err
		}
		if !rh.OK {
			if rh.Error == nil {
				rh.Error = &RemoteError{Code: CodeFailed}
			}
			return nil, rh.Error
		}
		return &Reply{Output: rh.Output, Body: r.Body}, nil
	case <-ctx.Done():
		go s.write(Frame{Type: FrameCancel, ID: id})
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrSessionClosed
	}
}

// Notify sends an EVENT.
func (s *Session) Notify(name string, data any, body []byte) error {
	h := EventHeader{Name: name}
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("vgp: encode event: %w", err)
		}
		h.Data = b
	}
	f, err := NewFrame(FrameEvent, 0, h, body)
	if err != nil {
		return err
	}
	return s.write(f)
}

// Close sends CLOSE with code and ends the session; Run returns
// ErrSessionClosed.
func (s *Session) Close(code, message string) {
	s.once.Do(func() {
		s.err = ErrSessionClosed
		s.conn.SendClose(code, message)
		s.cancel()
		close(s.done)
	})
}

func (s *Session) finish(err error) {
	s.once.Do(func() {
		s.err = err
		s.cancel()
		close(s.done)
		_ = s.conn.Close()
	})
}

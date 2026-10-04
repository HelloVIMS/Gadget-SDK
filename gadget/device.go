// Package gadget is the device side of the VIMS Gadget Protocol. Describe
// the gadget and its commands, give it a Store, call Run: it waits to be
// paired, keeps a session to its VIMS host up across network changes and
// reboots, and serves the host's calls.
//
//	dev, _ := gadget.New(gadget.Config{
//		Name:     "Desk lamp",
//		Commands: []gadget.Command{lightSet},
//		Store:    store,
//	})
//	go dev.Run(ctx)
//	res, err := dev.Pair(ctx, "vimsgadget1:…") // once, with the URI from VIMS
package gadget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hellovims/gadget-sdk/protocol"
	"github.com/hellovims/gadget-sdk/protocol/wscarrier"
)

// Session timing (PROTOCOL.md §8).
const (
	PingInterval   = 25 * time.Second
	IdleTimeout    = 60 * time.Second
	minBackoff     = time.Second
	maxBackoff     = time.Minute
	maxStoredAddrs = protocol.MaxPairingAddrs
)

// ErrOffline is returned by calls made while no session is up.
var ErrOffline = errors.New("gadget: not connected to the host")

// State is where a gadget is in its lifecycle.
type State string

// States.
const (
	StateUnpaired     State = "unpaired"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateStopped      State = "stopped"
)

// Status is a snapshot of the gadget's connection.
type Status struct {
	State     State     `json:"state"`
	ID        string    `json:"id"`
	Host      string    `json:"host,omitempty"`
	Addr      string    `json:"addr,omitempty"`
	Since     time.Time `json:"since"`
	LastError string    `json:"last_error,omitempty"`
}

// Config describes a gadget.
type Config struct {
	// Name is how the gadget introduces itself (1-64 characters); the owner
	// can rename it in VIMS.
	Name                      string
	Model, Platform, Firmware string
	// Caps describes hardware (display, audio, lights, buttons); free-form.
	Caps     map[string]any
	Commands []Command
	Store    Store
	// Limits are what this gadget can receive; zero means DefaultLimits.
	// Boards with little memory lower MaxChunk and MaxMessage.
	Limits protocol.Limits
	// Dial opens a carrier to host:port; nil means WebSocket.
	Dial func(ctx context.Context, addr string) (protocol.Carrier, error)
	// OnStatus is called on every state change; keep it fast.
	OnStatus func(Status)
	// OnEvent receives EVENT frames from the host; keep it fast.
	OnEvent func(*protocol.Event)
	Logger  *slog.Logger
}

// PairResult is the outcome of a successful Pair.
type PairResult struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	// SAS should match the code VIMS shows for this pairing.
	SAS  string `json:"sas"`
	Addr string `json:"addr"`
}

type pairRequest struct {
	p      protocol.Pairing
	result chan pairOutcome
}

type pairOutcome struct {
	res PairResult
	err error
}

// Device is a running gadget.
type Device struct {
	cfg      Config
	log      *slog.Logger
	key      protocol.KeyPair
	id       string
	hello    protocol.Hello
	commands map[string]Command
	dial     func(ctx context.Context, addr string) (protocol.Carrier, error)

	running atomic.Bool
	pairCh  chan pairRequest

	mu     sync.Mutex
	sess   *protocol.Session
	status Status
}

// New validates cfg and loads (or creates) the gadget's key.
func New(cfg Config) (*Device, error) {
	if cfg.Store == nil {
		return nil, errors.New("gadget: Config.Store is required")
	}
	if cfg.Limits == (protocol.Limits{}) {
		cfg.Limits = protocol.DefaultLimits
	}
	commands, infos, err := buildCommands(cfg.Commands)
	if err != nil {
		return nil, err
	}
	hello := protocol.Hello{Name: cfg.Name, Model: cfg.Model, Platform: cfg.Platform, Firmware: cfg.Firmware, Commands: infos, Limits: cfg.Limits}
	if len(cfg.Caps) > 0 {
		if hello.Caps, err = json.Marshal(cfg.Caps); err != nil {
			return nil, fmt.Errorf("gadget: caps: %w", err)
		}
	}
	if err := hello.Validate(); err != nil {
		return nil, err
	}
	key, err := cfg.Store.Key()
	if err != nil {
		return nil, err
	}
	d := &Device{
		cfg:      cfg,
		log:      cfg.Logger,
		key:      key,
		id:       protocol.DeviceID(key.Public),
		hello:    hello,
		commands: commands,
		dial:     cfg.Dial,
		pairCh:   make(chan pairRequest),
	}
	if d.log == nil {
		d.log = slog.Default()
	}
	if d.dial == nil {
		d.dial = wscarrier.Dial
	}
	d.status = Status{State: StateStopped, ID: d.id, Since: time.Now()}
	return d, nil
}

// ID is the gadget's id, derived from its key.
func (d *Device) ID() string { return d.id }

// PublicKey is the gadget's static public key.
func (d *Device) PublicKey() protocol.Key { return d.key.Public }

// Status reports the current connection state.
func (d *Device) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status
}

func (d *Device) setStatus(state State, host, addr string, err error) {
	d.mu.Lock()
	s := Status{State: state, ID: d.id, Host: host, Addr: addr, Since: time.Now()}
	if err != nil {
		s.LastError = err.Error()
	}
	if s.State == d.status.State && s.Host == d.status.Host && s.Addr == d.status.Addr && s.LastError == d.status.LastError {
		d.mu.Unlock()
		return
	}
	d.status = s
	d.mu.Unlock()
	if d.cfg.OnStatus != nil {
		d.cfg.OnStatus(s)
	}
}

func (d *Device) session() *protocol.Session {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sess
}

func (d *Device) setSession(s *protocol.Session) {
	d.mu.Lock()
	d.sess = s
	d.mu.Unlock()
}

// Run keeps the gadget connected until ctx ends. Unpaired, it waits for
// Pair; paired, it connects, serves the host and reconnects with backoff.
// When the host says the gadget is no longer paired (removed in VIMS), the
// pairing is forgotten and Run waits for Pair again.
func (d *Device) Run(ctx context.Context) error {
	if !d.running.CompareAndSwap(false, true) {
		return errors.New("gadget: Run called twice")
	}
	defer d.running.Store(false)
	defer d.setStatus(StateStopped, "", "", nil)
	attempt := 0
	var pending *pairRequest
	for {
		if err := ctx.Err(); err != nil {
			if pending != nil {
				pending.result <- pairOutcome{err: err}
			}
			return err
		}
		if pending != nil {
			req := *pending
			pending = d.pairAndServe(ctx, req)
			attempt = 0
			continue
		}
		p, err := d.cfg.Store.Pairing()
		if err != nil {
			return err
		}
		if p == nil {
			d.setStatus(StateUnpaired, "", "", nil)
			select {
			case req := <-d.pairCh:
				pending = &req
			case <-ctx.Done():
			}
			continue
		}
		state := StateConnecting
		if attempt > 0 {
			state = StateReconnecting
		}
		d.setStatus(state, p.HostName, "", nil)
		hostKey, _ := p.key()
		sess, w, addr, err := d.connect(ctx, hostKey, p.Addrs, protocol.ClientHello{Mode: protocol.ModeResume})
		if err != nil {
			if d.forgetIfUnpaired(err) {
				continue
			}
			attempt++
			wait := backoff(attempt)
			d.log.Warn("gadget: cannot reach host", "host", p.HostName, "retry_in", wait.Round(time.Second), "err", err)
			d.setStatus(StateReconnecting, p.HostName, "", err)
			select {
			case <-time.After(wait):
			case req := <-d.pairCh:
				pending = &req
			case <-ctx.Done():
			}
			continue
		}
		attempt = 0
		d.remember(p, w, addr)
		d.log.Info("gadget: connected", "id", d.id, "host", w.Host, "addr", addr)
		pending = d.serve(ctx, sess, w.Host, addr, nil)
	}
}

// forgetIfUnpaired clears the pairing when the host refused or closed the
// gadget as unknown or removed.
func (d *Device) forgetIfUnpaired(err error) bool {
	var he *protocol.HandshakeError
	var ce *protocol.CloseError
	switch {
	case errors.As(err, &he) && he.Code == protocol.RefuseUnpaired,
		errors.As(err, &ce) && ce.Code == protocol.CloseRevoked:
	default:
		return false
	}
	d.log.Warn("gadget: the host removed this gadget; waiting to be paired again", "err", err)
	if cerr := d.cfg.Store.ClearPairing(); cerr != nil {
		d.log.Error("gadget: forget pairing", "err", cerr)
	}
	return true
}

// serve runs a session until it ends, ctx ends or Pair is called; it
// returns that pair request, if any. ready runs once the session is live.
func (d *Device) serve(ctx context.Context, sess *protocol.Session, host, addr string, ready func()) *pairRequest {
	d.setSession(sess)
	defer d.setSession(nil)
	d.setStatus(StateConnected, host, addr, nil)
	done := make(chan error, 1)
	go func() { done <- sess.Run() }()
	if ready != nil {
		ready()
	}
	select {
	case err := <-done:
		if !d.forgetIfUnpaired(err) {
			d.log.Warn("gadget: session ended", "err", err)
		}
		return nil
	case req := <-d.pairCh:
		sess.Close(protocol.CloseShutdown, "pairing with another host")
		<-done
		return &req
	case <-ctx.Done():
		sess.Close(protocol.CloseShutdown, "gadget stopping")
		<-done
		return nil
	}
}

// pairAndServe pairs with the host in req and, on success, serves the new
// session. It returns a pair request that arrived meanwhile, if any.
func (d *Device) pairAndServe(ctx context.Context, req pairRequest) *pairRequest {
	d.setStatus(StateConnecting, req.p.HostName, "", nil)
	sess, w, addr, err := d.connect(ctx, req.p.HostKey, req.p.Addrs, protocol.ClientHello{Mode: protocol.ModePair, Token: req.p.Token.String()})
	if err != nil {
		req.result <- pairOutcome{err: err}
		return nil
	}
	host := w.Host
	if host == "" {
		host = req.p.HostName
	}
	rec := &Pairing{DeviceID: w.ID, HostKey: req.p.HostKey.String(), HostName: host, Addrs: mergeAddrs(addr, w.Addrs, req.p.Addrs), PairedAt: time.Now().UTC()}
	if err := d.cfg.Store.SavePairing(rec); err != nil {
		sess.Close(protocol.CloseShutdown, "gadget could not store the pairing")
		req.result <- pairOutcome{err: fmt.Errorf("gadget: store pairing: %w", err)}
		return nil
	}
	d.log.Info("gadget: paired", "id", w.ID, "host", host, "addr", addr)
	res := PairResult{ID: w.ID, Host: host, SAS: sess.Conn().SAS(), Addr: addr}
	return d.serve(ctx, sess, host, addr, func() { req.result <- pairOutcome{res: res} })
}

// connect tries addrs in order and returns the first established session.
// A refusal from a host stops the search: the host answered.
func (d *Device) connect(ctx context.Context, hostKey protocol.Key, addrs []string, ch protocol.ClientHello) (*protocol.Session, protocol.Welcome, string, error) {
	var lastErr error
	for _, addr := range addrs {
		if err := ctx.Err(); err != nil {
			return nil, protocol.Welcome{}, "", err
		}
		c, err := d.dial(ctx, addr)
		if err != nil {
			lastErr = err
			continue
		}
		conn, sh, err := protocol.ClientHandshake(c, d.key, hostKey, ch, protocol.HandshakeTimeout)
		if err != nil {
			c.Close()
			var he *protocol.HandshakeError
			if errors.As(err, &he) {
				return nil, protocol.Welcome{}, "", err
			}
			lastErr = err
			continue
		}
		w, err := conn.ExchangeHello(d.hello, protocol.HandshakeTimeout)
		if err != nil {
			conn.Close()
			var ce *protocol.CloseError
			if errors.As(err, &ce) {
				return nil, protocol.Welcome{}, "", err
			}
			lastErr = err
			continue
		}
		if sh.ID != d.id || w.ID != d.id {
			conn.SendClose(protocol.CloseProtocolError, "id does not match this gadget's key")
			return nil, protocol.Welcome{}, "", fmt.Errorf("gadget: host assigned id %s, this gadget is %s", w.ID, d.id)
		}
		return protocol.NewSession(conn, protocol.SessionConfig{Handler: d, Initiator: true, PingInterval: PingInterval, IdleTimeout: IdleTimeout}), w, addr, nil
	}
	if lastErr == nil {
		lastErr = errors.New("gadget: no host address")
	}
	return nil, protocol.Welcome{}, "", lastErr
}

// remember stores the host's current addresses, the one that worked first.
func (d *Device) remember(p *Pairing, w protocol.Welcome, addr string) {
	addrs := mergeAddrs(addr, w.Addrs, p.Addrs)
	host := w.Host
	if host == "" {
		host = p.HostName
	}
	if slices.Equal(addrs, p.Addrs) && host == p.HostName {
		return
	}
	next := *p
	next.Addrs, next.HostName = addrs, host
	if err := d.cfg.Store.SavePairing(&next); err != nil {
		d.log.Error("gadget: store host addresses", "err", err)
	}
}

func mergeAddrs(first string, lists ...[]string) []string {
	out := []string{first}
	for _, l := range lists {
		for _, a := range l {
			if !slices.Contains(out, a) && protocol.ValidateAddr(a) == nil {
				out = append(out, a)
			}
		}
	}
	return out[:min(len(out), maxStoredAddrs)]
}

func backoff(attempt int) time.Duration {
	d := minBackoff << min(attempt-1, 6)
	d = min(d, maxBackoff)
	jitter := time.Duration(rand.Int64N(int64(d) / 5))
	return d - d/10 + jitter
}

// Pair pairs the gadget with the host in a pairing URI from VIMS (Settings
// → Devices → Add device), replacing any previous host. Run carries the
// pairing out: Pair waits for it until the pairing completes or ctx ends.
func (d *Device) Pair(ctx context.Context, uri string) (PairResult, error) {
	p, err := protocol.ParsePairingURI(uri)
	if err != nil {
		return PairResult{}, err
	}
	if p.Expired(time.Now()) {
		return PairResult{}, errors.New("gadget: this pairing URI has expired; create a new one in VIMS")
	}
	req := pairRequest{p: p, result: make(chan pairOutcome, 1)}
	select {
	case d.pairCh <- req:
	case <-ctx.Done():
		return PairResult{}, ctx.Err()
	}
	select {
	case out := <-req.result:
		return out.res, out.err
	case <-ctx.Done():
		return PairResult{}, ctx.Err()
	}
}

// Unpair forgets the host and closes the session. The host keeps listing
// the gadget until the owner removes it there.
func (d *Device) Unpair() error {
	if err := d.cfg.Store.ClearPairing(); err != nil {
		return err
	}
	if s := d.session(); s != nil {
		s.Close(protocol.CloseShutdown, "unpaired on the gadget")
	}
	return nil
}

// Call invokes a host service.
func (d *Device) Call(ctx context.Context, service string, input any, body []byte) (*protocol.Reply, error) {
	s := d.session()
	if s == nil {
		return nil, ErrOffline
	}
	return s.Call(ctx, service, input, body)
}

// SendMessage sends the owner a message (PROTOCOL.md §7, message.send);
// thread groups messages into a side conversation.
func (d *Device) SendMessage(ctx context.Context, text, thread string) (protocol.MessageOutput, error) {
	in := protocol.MessageInput{Text: text, Thread: thread}
	if err := in.Validate(); err != nil {
		return protocol.MessageOutput{}, err
	}
	r, err := d.Call(ctx, protocol.ServiceMessageSend, in, nil)
	if err != nil {
		return protocol.MessageOutput{}, err
	}
	var out protocol.MessageOutput
	if err := r.DecodeOutput(&out); err != nil {
		return protocol.MessageOutput{}, fmt.Errorf("gadget: message.send reply: %w", err)
	}
	return out, nil
}

// Notify sends the host an EVENT.
func (d *Device) Notify(name string, data any, body []byte) error {
	s := d.session()
	if s == nil {
		return ErrOffline
	}
	return s.Notify(name, data, body)
}

// HandleCall implements protocol.Handler.
func (d *Device) HandleCall(ctx context.Context, call *protocol.Call) (*protocol.Reply, error) {
	c, ok := d.commands[call.Command]
	if !ok {
		return nil, protocol.Errorf(protocol.CodeUnknownCommand, "this gadget has no command %q", call.Command)
	}
	return runCommand(ctx, c, call)
}

// HandleEvent implements protocol.Handler.
func (d *Device) HandleEvent(ev *protocol.Event) {
	if d.cfg.OnEvent != nil {
		d.cfg.OnEvent(ev)
	}
}

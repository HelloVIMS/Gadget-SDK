package protocol

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const (
	chunkMore     = 0x01
	tagSize       = 16
	chunkOverhead = 1 + tagSize
	// WriteTimeout bounds each transport message write.
	WriteTimeout = 30 * time.Second
)

// ErrFrameTooLarge is returned by WriteFrame for a frame the peer would
// refuse; nothing is sent.
var ErrFrameTooLarge = errors.New("vgp: frame exceeds the peer's max_message")

// Conn is an established, encrypted VGP connection: it chunks, encrypts and
// reassembles frames. One goroutine may read while others write.
type Conn struct {
	carrier Carrier
	hash    []byte
	remote  Key

	wmu  sync.Mutex
	send *noise.CipherState
	peer Limits

	recv  *noise.CipherState
	lmu   sync.Mutex
	local Limits
}

func newConn(c Carrier, send, recv *noise.CipherState, hash []byte, remote Key) *Conn {
	return &Conn{carrier: c, send: send, recv: recv, hash: append([]byte{}, hash...), remote: remote}
}

func (c *Conn) setLimits(local, peer Limits) {
	c.lmu.Lock()
	c.local = local
	c.lmu.Unlock()
	c.wmu.Lock()
	c.peer = peer
	c.wmu.Unlock()
}

func (c *Conn) setLocal(l Limits) {
	c.lmu.Lock()
	c.local = l
	c.lmu.Unlock()
}

func (c *Conn) setPeer(l Limits) {
	c.wmu.Lock()
	c.peer = l
	c.wmu.Unlock()
}

// LocalLimits are what this side accepts.
func (c *Conn) LocalLimits() Limits {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	return c.local
}

// PeerLimits are what the peer accepts.
func (c *Conn) PeerLimits() Limits {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.peer
}

// RemoteKey is the peer's static key.
func (c *Conn) RemoteKey() Key { return c.remote }

// HandshakeHash is the Noise handshake hash, unique to this session.
func (c *Conn) HandshakeHash() []byte { return append([]byte{}, c.hash...) }

// SAS is this session's short authentication string.
func (c *Conn) SAS() string { return SAS(c.hash) }

// RemoteAddr describes the peer's network address.
func (c *Conn) RemoteAddr() string { return c.carrier.RemoteAddr() }

// SetReadDeadline bounds the next ReadFrame.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.carrier.SetReadDeadline(t) }

// Close closes the carrier.
func (c *Conn) Close() error { return c.carrier.Close() }

// WriteFrame encodes, chunks and encrypts f and sends it. Chunks of one
// frame are never interleaved with another frame's.
func (c *Conn) WriteFrame(f Frame) error {
	b, err := encodeFrame(f)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if len(b) > c.peer.MaxMessage {
		return fmt.Errorf("%w (%s of %d bytes, limit %d)", ErrFrameTooLarge, f.Type, len(b), c.peer.MaxMessage)
	}
	maxData := c.peer.MaxChunk - chunkOverhead
	plain := make([]byte, 0, min(len(b), maxData)+1)
	sealed := make([]byte, 0, cap(plain)+tagSize)
	for off := 0; off < len(b); {
		n := min(len(b)-off, maxData)
		flags := byte(0)
		if off+n < len(b) {
			flags = chunkMore
		}
		plain = append(append(plain[:0], flags), b[off:off+n]...)
		sealed, err = c.send.Encrypt(sealed[:0], nil, plain)
		if err != nil {
			return fmt.Errorf("vgp: encrypt: %w", err)
		}
		_ = c.carrier.SetWriteDeadline(time.Now().Add(WriteTimeout))
		if err := c.carrier.WriteMessage(sealed); err != nil {
			return fmt.Errorf("vgp: send: %w", err)
		}
		off += n
	}
	return nil
}

// ReadFrame receives, decrypts and reassembles the next frame. It must not
// be called concurrently with itself.
func (c *Conn) ReadFrame() (Frame, error) {
	limits := c.LocalLimits()
	var assembled []byte
	for {
		sealed, err := c.carrier.ReadMessage()
		if err != nil {
			return Frame{}, err
		}
		if len(sealed) > limits.MaxChunk {
			return Frame{}, protocolErrorf("transport message of %d bytes exceeds max_chunk %d", len(sealed), limits.MaxChunk)
		}
		if len(sealed) < chunkOverhead {
			return Frame{}, protocolErrorf("transport message of %d bytes is too short", len(sealed))
		}
		plain, err := c.recv.Decrypt(nil, nil, sealed)
		if err != nil {
			return Frame{}, protocolErrorf("transport message did not authenticate")
		}
		flags := plain[0]
		if flags&^chunkMore != 0 {
			return Frame{}, protocolErrorf("reserved chunk flags 0x%02x set", flags)
		}
		if len(assembled)+len(plain)-1 > limits.MaxMessage {
			return Frame{}, protocolErrorf("frame exceeds max_message %d", limits.MaxMessage)
		}
		if assembled == nil && flags&chunkMore == 0 {
			assembled = plain[1:]
		} else {
			assembled = append(assembled, plain[1:]...)
		}
		if flags&chunkMore == 0 {
			return decodeFrame(assembled)
		}
	}
}

// ExchangeHello is the gadget's first exchange after the handshake: it sends
// HELLO and waits for WELCOME, then applies both sides' limits.
func (c *Conn) ExchangeHello(h Hello, timeout time.Duration) (Welcome, error) {
	h.Commands = append([]CommandInfo(nil), h.Commands...)
	if err := h.Validate(); err != nil {
		return Welcome{}, err
	}
	f, err := NewFrame(FrameHello, 0, h, nil)
	if err != nil {
		return Welcome{}, err
	}
	if f.Size() > MaxHelloSize {
		return Welcome{}, fmt.Errorf("vgp: HELLO of %d bytes exceeds %d", f.Size(), MaxHelloSize)
	}
	c.setLocal(h.Limits)
	if err := c.WriteFrame(f); err != nil {
		return Welcome{}, err
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	reply, err := c.ReadFrame()
	if err != nil {
		return Welcome{}, fmt.Errorf("vgp: waiting for WELCOME: %w", err)
	}
	if reply.Type == FrameClose {
		var ce CloseError
		_ = reply.DecodeHeader(&ce)
		return Welcome{}, &ce
	}
	if reply.Type != FrameWelcome {
		return Welcome{}, protocolErrorf("expected WELCOME, got %s", reply.Type)
	}
	var w Welcome
	if err := reply.DecodeHeader(&w); err != nil {
		return Welcome{}, err
	}
	if err := w.Validate(); err != nil {
		return Welcome{}, &ProtocolError{msg: err.Error()}
	}
	c.setPeer(w.Limits)
	return w, nil
}

// ReadHello is the host's first read after the handshake. The HELLO is
// validated and the gadget's limits applied to what the host sends.
func (c *Conn) ReadHello(timeout time.Duration) (Hello, error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	f, err := c.ReadFrame()
	if err != nil {
		return Hello{}, fmt.Errorf("vgp: waiting for HELLO: %w", err)
	}
	if f.Type != FrameHello {
		return Hello{}, protocolErrorf("expected HELLO, got %s", f.Type)
	}
	var h Hello
	if err := f.DecodeHeader(&h); err != nil {
		return Hello{}, err
	}
	if err := h.Validate(); err != nil {
		return Hello{}, &ProtocolError{msg: err.Error()}
	}
	c.setPeer(h.Limits)
	return h, nil
}

// SendWelcome answers HELLO and applies the host's own limits.
func (c *Conn) SendWelcome(w Welcome) error {
	if err := w.Validate(); err != nil {
		return err
	}
	f, err := NewFrame(FrameWelcome, 0, w, nil)
	if err != nil {
		return err
	}
	c.setLocal(w.Limits)
	return c.WriteFrame(f)
}

// SendClose writes a CLOSE frame (best effort, short deadline) and closes
// the carrier.
func (c *Conn) SendClose(code, message string) {
	if f, err := NewFrame(FrameClose, 0, CloseError{Code: code, Message: message}, nil); err == nil {
		c.wmu.Lock()
		ok := c.peer.MaxMessage > 0
		c.wmu.Unlock()
		if ok {
			done := make(chan struct{})
			go func() {
				_ = c.WriteFrame(f)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
		}
	}
	_ = c.carrier.Close()
}

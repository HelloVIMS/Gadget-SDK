package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/flynn/noise"
)

var (
	cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	// Prologue binds every handshake to this protocol version.
	Prologue = []byte("vims-gadget/1")
)

// Mode is how a gadget opens a session (PROTOCOL.md §3).
type Mode string

// Modes.
const (
	ModePair   Mode = "pair"
	ModeResume Mode = "resume"
)

// ClientHello is the payload of handshake message 1.
type ClientHello struct {
	Mode  Mode   `json:"m"`
	Token string `json:"t,omitempty"`
}

// ServerHello is the payload of handshake message 2.
type ServerHello struct {
	OK      bool   `json:"ok"`
	ID      string `json:"id,omitempty"`
	Host    string `json:"host,omitempty"`
	Error   string `json:"e,omitempty"`
	Message string `json:"msg,omitempty"`
}

// Accept is message 2 for an accepted gadget.
func Accept(id, host string) ServerHello { return ServerHello{OK: true, ID: id, Host: host} }

// Refuse is message 2 for a refused gadget.
func Refuse(code, format string, args ...any) ServerHello {
	return ServerHello{Error: code, Message: fmt.Sprintf(format, args...)}
}

// HandshakeTimeout bounds both handshake messages.
const HandshakeTimeout = 10 * time.Second

func dhKey(kp KeyPair) noise.DHKey {
	priv, pub := kp.Private, kp.Public
	return noise.DHKey{Private: priv[:], Public: pub[:]}
}

// ClientHandshake runs the gadget's side of the handshake: it proves the
// gadget's key to the host whose key it pins, and returns the encrypted
// connection with the host's answer. A refusal is a *HandshakeError.
func ClientHandshake(c Carrier, local KeyPair, host Key, hello ClientHello, timeout time.Duration) (*Conn, ServerHello, error) {
	return clientHandshake(c, local, host, hello, timeout, nil)
}

// clientHandshake takes the ephemeral key's randomness from random
// (crypto/rand when nil); test vectors fix it.
func clientHandshake(c Carrier, local KeyPair, host Key, hello ClientHello, timeout time.Duration, random io.Reader) (*Conn, ServerHello, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      Prologue,
		StaticKeypair: dhKey(local),
		Random:        random,
		PeerStatic:    append([]byte{}, host[:]...),
	})
	if err != nil {
		return nil, ServerHello{}, fmt.Errorf("vgp: handshake setup: %w", err)
	}
	payload, err := json.Marshal(hello)
	if err != nil || len(payload) > maxHandshakeBody {
		return nil, ServerHello{}, errors.New("vgp: message 1 payload too large")
	}
	msg1, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, ServerHello{}, fmt.Errorf("vgp: write message 1: %w", err)
	}
	deadline := time.Now().Add(timeout)
	_ = c.SetWriteDeadline(deadline)
	if err := c.WriteMessage(msg1); err != nil {
		return nil, ServerHello{}, fmt.Errorf("vgp: send message 1: %w", err)
	}
	_ = c.SetReadDeadline(deadline)
	msg2, err := c.ReadMessage()
	if err != nil {
		return nil, ServerHello{}, fmt.Errorf("vgp: receive message 2: %w", err)
	}
	body, send, recv, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, ServerHello{}, fmt.Errorf("vgp: message 2 did not authenticate as the pinned host: %w", err)
	}
	if send == nil || recv == nil {
		return nil, ServerHello{}, protocolErrorf("handshake did not complete after message 2")
	}
	var sh ServerHello
	if err := json.Unmarshal(body, &sh); err != nil {
		return nil, ServerHello{}, protocolErrorf("message 2 payload: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	_ = c.SetWriteDeadline(time.Time{})
	if !sh.OK {
		if sh.Error == "" {
			sh.Error = RefuseVersion
		}
		return nil, sh, &HandshakeError{Code: sh.Error, Message: sh.Message}
	}
	if !ValidDeviceID(sh.ID) {
		return nil, sh, protocolErrorf("message 2 carries an invalid id %q", sh.ID)
	}
	conn := newConn(c, send, recv, hs.ChannelBinding(), host)
	conn.setLimits(Limits{}, preWelcomeLimits)
	return conn, sh, nil
}

// ServerHandshake runs the host's side. decide receives the gadget's static
// key and message 1's payload and returns message 2's payload. When decide
// refuses, the refusal is sent and a *HandshakeError returned; the caller
// closes the carrier either way on error.
func ServerHandshake(c Carrier, local KeyPair, timeout time.Duration, decide func(remote Key, hello ClientHello) ServerHello) (*Conn, ClientHello, error) {
	return serverHandshake(c, local, timeout, decide, nil)
}

func serverHandshake(c Carrier, local KeyPair, timeout time.Duration, decide func(remote Key, hello ClientHello) ServerHello, random io.Reader) (*Conn, ClientHello, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      Prologue,
		StaticKeypair: dhKey(local),
		Random:        random,
	})
	if err != nil {
		return nil, ClientHello{}, fmt.Errorf("vgp: handshake setup: %w", err)
	}
	deadline := time.Now().Add(timeout)
	_ = c.SetReadDeadline(deadline)
	msg1, err := c.ReadMessage()
	if err != nil {
		return nil, ClientHello{}, fmt.Errorf("vgp: receive message 1: %w", err)
	}
	if len(msg1) > 32+48+maxHandshakeBody+16 {
		return nil, ClientHello{}, protocolErrorf("message 1 of %d bytes is too large", len(msg1))
	}
	body, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, ClientHello{}, protocolErrorf("message 1 did not decrypt: %v", err)
	}
	var remote Key
	copy(remote[:], hs.PeerStatic())
	var ch ClientHello
	var sh ServerHello
	if err := json.Unmarshal(body, &ch); err != nil {
		sh = Refuse(RefuseVersion, "message 1 payload is not a VGP/1 hello")
	} else if ch.Mode != ModePair && ch.Mode != ModeResume {
		sh = Refuse(RefuseVersion, "unknown mode %q", ch.Mode)
	} else {
		sh = decide(remote, ch)
	}
	payload, err := json.Marshal(sh)
	if err != nil || len(payload) > maxHandshakeBody {
		return nil, ch, errors.New("vgp: message 2 payload too large")
	}
	msg2, cs1, cs2, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, ch, fmt.Errorf("vgp: write message 2: %w", err)
	}
	_ = c.SetWriteDeadline(deadline)
	if err := c.WriteMessage(msg2); err != nil {
		return nil, ch, fmt.Errorf("vgp: send message 2: %w", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	_ = c.SetWriteDeadline(time.Time{})
	if !sh.OK {
		return nil, ch, &HandshakeError{Code: sh.Error, Message: sh.Message}
	}
	conn := newConn(c, cs2, cs1, hs.ChannelBinding(), remote)
	conn.setLimits(preWelcomeLimits, Limits{})
	return conn, ch, nil
}

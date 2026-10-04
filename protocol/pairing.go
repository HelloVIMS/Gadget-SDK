package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// PairingScheme prefixes every pairing URI.
	PairingScheme = "vimsgadget1:"
	// TokenSize is the length of a pairing token.
	TokenSize = 32
	// MaxPairingAddrs bounds the addresses a pairing URI may list.
	MaxPairingAddrs = 8
	// MaxPairingURI bounds the length of a pairing URI.
	MaxPairingURI  = 2048
	maxHostNameLen = 64
)

// Token is a one-time pairing token.
type Token [TokenSize]byte

// NewToken returns a random token from r (crypto/rand when nil).
func NewToken(r io.Reader) (Token, error) {
	if r == nil {
		r = rand.Reader
	}
	var t Token
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return t, fmt.Errorf("vgp: generate token: %w", err)
	}
	return t, nil
}

// String is the unpadded base64url form sent in message 1.
func (t Token) String() string { return base64.RawURLEncoding.EncodeToString(t[:]) }

// ParseToken decodes the unpadded base64url form of a token.
func ParseToken(s string) (Token, error) {
	var t Token
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != TokenSize {
		return t, errors.New("vgp: token must be 32 bytes of unpadded base64url")
	}
	copy(t[:], b)
	return t, nil
}

// Pairing is the content of a pairing URI (PROTOCOL.md §4).
type Pairing struct {
	HostKey  Key
	Addrs    []string
	Token    Token
	Expires  time.Time
	HostName string
}

type pairingWire struct {
	V int      `json:"v"`
	K string   `json:"k"`
	A []string `json:"a"`
	T string   `json:"t"`
	E int64    `json:"e"`
	N string   `json:"n,omitempty"`
}

// URI encodes p as a pairing URI.
func (p Pairing) URI() (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(pairingWire{V: 1, K: p.HostKey.String(), A: p.Addrs, T: p.Token.String(), E: p.Expires.Unix(), N: p.HostName})
	if err != nil {
		return "", err
	}
	uri := PairingScheme + base64.RawURLEncoding.EncodeToString(b)
	if len(uri) > MaxPairingURI {
		return "", errors.New("vgp: pairing URI too long; list fewer addresses")
	}
	return uri, nil
}

// Expired reports whether the pairing has expired at now.
func (p Pairing) Expired(now time.Time) bool { return !now.Before(p.Expires) }

// ParsePairingURI decodes and validates a pairing URI. It does not check
// expiry: callers decide against their own clock with Expired.
func ParsePairingURI(uri string) (Pairing, error) {
	uri = strings.TrimSpace(uri)
	if len(uri) > MaxPairingURI {
		return Pairing{}, errors.New("vgp: pairing URI too long")
	}
	if !strings.HasPrefix(uri, PairingScheme) {
		return Pairing{}, fmt.Errorf("vgp: a pairing URI starts with %q", PairingScheme)
	}
	raw, err := base64.RawURLEncoding.DecodeString(uri[len(PairingScheme):])
	if err != nil {
		return Pairing{}, errors.New("vgp: pairing URI is not valid base64url")
	}
	var w pairingWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return Pairing{}, errors.New("vgp: pairing URI does not hold a JSON object")
	}
	if w.V != 1 {
		return Pairing{}, fmt.Errorf("vgp: pairing URI version %d is not supported", w.V)
	}
	p := Pairing{Addrs: w.A, Expires: time.Unix(w.E, 0), HostName: w.N}
	if p.HostKey, err = ParseKey(w.K); err != nil {
		return Pairing{}, err
	}
	if p.Token, err = ParseToken(w.T); err != nil {
		return Pairing{}, err
	}
	if w.E <= 0 {
		return Pairing{}, errors.New("vgp: pairing URI has no expiry")
	}
	if err := p.validate(); err != nil {
		return Pairing{}, err
	}
	return p, nil
}

func (p Pairing) validate() error {
	if p.HostKey.IsZero() {
		return errors.New("vgp: pairing has no host key")
	}
	if len(p.Addrs) == 0 || len(p.Addrs) > MaxPairingAddrs {
		return fmt.Errorf("vgp: pairing must list 1-%d addresses", MaxPairingAddrs)
	}
	for _, a := range p.Addrs {
		if err := ValidateAddr(a); err != nil {
			return err
		}
	}
	if p.Expires.IsZero() {
		return errors.New("vgp: pairing has no expiry")
	}
	if utf8.RuneCountInString(p.HostName) > maxHostNameLen || !printable(p.HostName) {
		return errors.New("vgp: pairing host name is invalid")
	}
	return nil
}

// ValidateAddr checks a host:port address as used in pairings and WELCOME.
func ValidateAddr(a string) error {
	if len(a) > 261 {
		return fmt.Errorf("vgp: address %.32q… is too long", a)
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil || host == "" {
		return fmt.Errorf("vgp: address %q is not host:port", a)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("vgp: address %q has an invalid port", a)
	}
	if strings.ContainsAny(host, "/?#@ ") {
		return fmt.Errorf("vgp: address %q has an invalid host", a)
	}
	return nil
}

// printable reports whether s has no control characters.
func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return utf8.ValidString(s)
}

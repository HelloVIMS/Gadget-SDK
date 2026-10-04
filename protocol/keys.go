package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the length of a Curve25519 key.
const KeySize = 32

// Key is a static public key.
type Key [KeySize]byte

// String is the unpadded base64url form used in pairing URIs and APIs.
func (k Key) String() string { return base64.RawURLEncoding.EncodeToString(k[:]) }

// IsZero reports whether k is unset.
func (k Key) IsZero() bool { return k == Key{} }

// ParseKey decodes the unpadded base64url form of a key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != KeySize {
		return k, errors.New("vgp: key must be 32 bytes of unpadded base64url")
	}
	copy(k[:], b)
	if k.IsZero() {
		return k, errors.New("vgp: key is all zeros")
	}
	return k, nil
}

// KeyPair is a static key pair.
type KeyPair struct {
	Private [KeySize]byte
	Public  Key
}

// GenerateKeyPair creates a key pair from r (crypto/rand when nil).
func GenerateKeyPair(r io.Reader) (KeyPair, error) {
	if r == nil {
		r = rand.Reader
	}
	var priv [KeySize]byte
	if _, err := io.ReadFull(r, priv[:]); err != nil {
		return KeyPair{}, fmt.Errorf("vgp: generate key: %w", err)
	}
	return keyPairFrom(priv)
}

// KeyPairFromPrivate rebuilds a key pair from its 32-byte private key.
func KeyPairFromPrivate(priv []byte) (KeyPair, error) {
	if len(priv) != KeySize {
		return KeyPair{}, errors.New("vgp: private key must be 32 bytes")
	}
	var p [KeySize]byte
	copy(p[:], priv)
	return keyPairFrom(p)
}

func keyPairFrom(priv [KeySize]byte) (KeyPair, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("vgp: derive public key: %w", err)
	}
	kp := KeyPair{Private: priv}
	copy(kp.Public[:], pub)
	return kp, nil
}

var (
	idEncoding  = base32.StdEncoding.WithPadding(base32.NoPadding)
	idPattern   = regexp.MustCompile(`^g[a-z2-7]{16}$`)
	idDomain    = []byte("vgp/1 device-id\x00")
	sasDomain   = []byte("vgp/1 sas\x00")
	sasModulus  = uint32(1_000_000)
	sasHalfBase = uint32(1000)
)

// DeviceID derives a gadget's id from its static public key (PROTOCOL.md §1).
func DeviceID(pub Key) string {
	h := sha256.Sum256(append(append([]byte{}, idDomain...), pub[:]...))
	return "g" + strings.ToLower(idEncoding.EncodeToString(h[:10]))
}

// ValidDeviceID reports whether s has the form of a gadget id.
func ValidDeviceID(s string) bool { return idPattern.MatchString(s) }

// SAS is the short authentication string of a completed handshake
// (PROTOCOL.md §3): six digits both sides can display and compare.
func SAS(handshakeHash []byte) string {
	h := sha256.Sum256(append(append([]byte{}, sasDomain...), handshakeHash...))
	n := binary.BigEndian.Uint32(h[:4]) % sasModulus
	return fmt.Sprintf("%03d %03d", n/sasHalfBase, n%sasHalfBase)
}

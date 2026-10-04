package gadget

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hellovims/gadget-sdk/protocol"
)

// Pairing is what a gadget remembers about its host.
type Pairing struct {
	DeviceID string    `json:"device_id"`
	HostKey  string    `json:"host_key"`
	HostName string    `json:"host_name,omitempty"`
	Addrs    []string  `json:"addrs"`
	PairedAt time.Time `json:"paired_at"`
}

func (p *Pairing) key() (protocol.Key, error) { return protocol.ParseKey(p.HostKey) }

func (p *Pairing) validate() error {
	if _, err := p.key(); err != nil {
		return err
	}
	if !protocol.ValidDeviceID(p.DeviceID) {
		return fmt.Errorf("gadget: stored device id %q is invalid", p.DeviceID)
	}
	if len(p.Addrs) == 0 {
		return errors.New("gadget: stored pairing has no host address")
	}
	for _, a := range p.Addrs {
		if err := protocol.ValidateAddr(a); err != nil {
			return err
		}
	}
	return nil
}

// Store persists a gadget's static key and pairing. Implementations must be
// safe for concurrent use.
type Store interface {
	// Key returns the gadget's static key pair, creating it on first use.
	Key() (protocol.KeyPair, error)
	// Pairing returns the stored pairing, or nil when unpaired.
	Pairing() (*Pairing, error)
	SavePairing(*Pairing) error
	ClearPairing() error
}

// FileStore keeps the key and pairing in a directory: device.key (hex,
// 0600) and pairing.json (0600). The directory is created 0700.
type FileStore struct {
	dir string
	mu  sync.Mutex
}

const (
	keyFile     = "device.key"
	pairingFile = "pairing.json"
)

// NewFileStore opens (creating if needed) a store in dir.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("gadget: store directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("gadget: create %s: %w", dir, err)
	}
	return &FileStore{dir: dir}, nil
}

// Dir is the store's directory.
func (s *FileStore) Dir() string { return s.dir }

// Key implements Store.
func (s *FileStore) Key() (protocol.KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, keyFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		kp, err := protocol.GenerateKeyPair(nil)
		if err != nil {
			return protocol.KeyPair{}, err
		}
		if err := writeFileAtomic(path, []byte(hex.EncodeToString(kp.Private[:])+"\n")); err != nil {
			return protocol.KeyPair{}, err
		}
		return kp, nil
	}
	if err != nil {
		return protocol.KeyPair{}, fmt.Errorf("gadget: read %s: %w", path, err)
	}
	priv, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return protocol.KeyPair{}, fmt.Errorf("gadget: %s is not a hex key", path)
	}
	return protocol.KeyPairFromPrivate(priv)
}

// Pairing implements Store.
func (s *FileStore) Pairing() (*Pairing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, pairingFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gadget: read %s: %w", path, err)
	}
	var p Pairing
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("gadget: %s: %w", path, err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("gadget: %s: %w", path, err)
	}
	return &p, nil
}

// SavePairing implements Store.
func (s *FileStore) SavePairing(p *Pairing) error {
	if err := p.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileAtomic(filepath.Join(s.dir, pairingFile), append(b, '\n'))
}

// ClearPairing implements Store.
func (s *FileStore) ClearPairing() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.dir, pairingFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// writeFileAtomic replaces path with data (0600) so a crash leaves either
// the old or the new content.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

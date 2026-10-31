package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hellovims/gadget-sdk/protocol"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const maxReceipt = 2 * 1024 * 1024

type receipt struct {
	RequestID   string          `json:"request_id"`
	Operation   string          `json:"operation"`
	InputSHA256 string          `json:"input_sha256"`
	State       string          `json:"state"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Result      json.RawMessage `json:"result,omitempty"`
}
type receiptStore struct{ dir string }

func newReceiptStore(dir string) (*receiptStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("receipt directory must be private (0700)")
	}
	return &receiptStore{dir: dir}, nil
}
func (s *receiptStore) path(id string) (string, error) {
	if !requestIDPattern.MatchString(id) {
		return "", protocol.Errorf(protocol.CodeInvalidInput, "invalid request_id")
	}
	return filepath.Join(s.dir, id+".json"), nil
}
func (s *receiptStore) read(id string) (*receipt, error) {
	path, err := s.path(id)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "no receipt for request %s", id)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxReceipt+1))
	if err != nil {
		return nil, err
	}
	var r receipt
	if len(data) > maxReceipt || json.Unmarshal(data, &r) != nil || r.RequestID != id || len(r.InputSHA256) != 64 || (r.State != "pending" && r.State != "accepted" && r.State != "unknown") || (r.State == "accepted" && !json.Valid(r.Result)) {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "receipt for %s is incomplete or corrupt; refusing to replay", id)
	}
	return &r, nil
}
func syncDirectory(path string) error {
	// Go does not expose portable directory flushing on Windows. File contents
	// are still synced; see README for the power-loss durability limitation.
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *receiptStore) reserve(id, operation, digest string) (*receipt, bool, error) {
	path, err := s.path(id)
	if err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := s.read(id)
		if readErr != nil {
			return nil, false, readErr
		}
		if existing.Operation != operation || existing.InputSHA256 != digest {
			return nil, false, protocol.Errorf(protocol.CodeInvalidInput, "request_id %s was already used with different input or configuration", id)
		}
		return existing, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	now := time.Now().UTC()
	r := &receipt{RequestID: id, Operation: operation, InputSHA256: digest, State: "pending", CreatedAt: now, UpdatedAt: now}
	data, err := json.Marshal(r)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncDirectory(s.dir)
	}
	// Never remove an uncertain claim: an incomplete file must fail closed.
	if err != nil {
		return nil, false, fmt.Errorf("persist submission claim: %w", err)
	}
	return r, true, nil
}
func (s *receiptStore) finish(r *receipt) error {
	path, err := s.path(r.RequestID)
	if err != nil {
		return err
	}
	r.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".receipt-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDirectory(s.dir)
}

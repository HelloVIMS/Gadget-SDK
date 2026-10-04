//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
)

const (
	maxReadChunk   = 64 << 10
	maxWriteChunk  = 1 << 20
	uploadIdleTime = 15 * time.Minute
	maxUploads     = 16
)

var uploadIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type files struct {
	home string

	mu      sync.Mutex
	uploads map[string]*upload
}

type upload struct {
	target  string
	tmp     *os.File
	size    int64
	mode    os.FileMode
	touched time.Time
}

func newFiles(home string) *files {
	return &files{home: home, uploads: map[string]*upload{}}
}

type readInput struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset,omitempty"`
	Length int64  `json:"length,omitempty"`
}

type readOutput struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Offset  int64  `json:"offset"`
	Length  int    `json:"length"`
	EOF     bool   `json:"eof"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
}

func (f *files) read(_ context.Context, req *gadget.Request) (*gadget.Response, error) {
	var in readInput
	if err := req.Decode(&in); err != nil {
		return nil, err
	}
	path, err := resolve(f.home, in.Path)
	if err != nil {
		return nil, err
	}
	if in.Offset < 0 || in.Length < 0 {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "offset and length must not be negative")
	}
	length := in.Length
	if length == 0 || length > maxReadChunk {
		length = maxReadChunk
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, fsError(err)
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, fsError(err)
	}
	if st.IsDir() {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "%s is a directory", path)
	}
	buf := make([]byte, length)
	n, err := fh.ReadAt(buf, in.Offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fsError(err)
	}
	out := readOutput{
		Path:    path,
		Size:    st.Size(),
		Offset:  in.Offset,
		Length:  n,
		EOF:     in.Offset+int64(n) >= st.Size(),
		Mode:    fmt.Sprintf("%04o", st.Mode().Perm()),
		ModTime: st.ModTime().UTC().Format(time.RFC3339),
	}
	return &gadget.Response{Output: out, Body: buf[:n]}, nil
}

type writeInput struct {
	Path     string  `json:"path"`
	Content  *string `json:"content,omitempty"`
	Offset   int64   `json:"offset,omitempty"`
	Final    *bool   `json:"final,omitempty"`
	UploadID string  `json:"upload_id,omitempty"`
	Mode     string  `json:"mode,omitempty"`
	Mkdir    bool    `json:"mkdir,omitempty"`
}

type writeOutput struct {
	Path     string `json:"path"`
	Written  int    `json:"written"`
	Size     int64  `json:"size"`
	Complete bool   `json:"complete"`
}

func (f *files) write(_ context.Context, req *gadget.Request) (*gadget.Response, error) {
	var in writeInput
	if err := req.Decode(&in); err != nil {
		return nil, err
	}
	path, err := resolve(f.home, in.Path)
	if err != nil {
		return nil, err
	}
	data := req.Body
	if in.Content != nil {
		if len(data) > 0 {
			return nil, protocol.Errorf(protocol.CodeInvalidInput, "send content or a body, not both")
		}
		data = []byte(*in.Content)
	}
	if len(data) > maxWriteChunk {
		return nil, protocol.Errorf(protocol.CodeTooLarge, "chunks are at most %d bytes", maxWriteChunk)
	}
	final := in.Final == nil || *in.Final
	if in.Offset < 0 {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "offset must not be negative")
	}
	if in.UploadID == "" && (!final || in.Offset != 0) {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "chunked writes need an upload_id")
	}
	if in.UploadID != "" && !uploadIDPattern.MatchString(in.UploadID) {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "upload_id must be 1-64 of A-Z a-z 0-9 . _ -")
	}
	mode, err := parseMode(in.Mode)
	if err != nil {
		return nil, err
	}

	if in.UploadID == "" {
		up, err := startUpload(path, mode, in.Mkdir)
		if err != nil {
			return nil, err
		}
		if _, err := up.tmp.Write(data); err != nil {
			up.discard()
			return nil, fsError(err)
		}
		if err := up.commit(); err != nil {
			return nil, err
		}
		return &gadget.Response{Output: writeOutput{Path: path, Written: len(data), Size: int64(len(data)), Complete: true}}, nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.expireLocked(time.Now())
	key := in.UploadID
	up := f.uploads[key]
	if in.Offset == 0 {
		if up != nil {
			up.discard()
			delete(f.uploads, key)
		}
		if len(f.uploads) >= maxUploads {
			return nil, protocol.Errorf(protocol.CodeBusy, "%d uploads already in progress", maxUploads)
		}
		if up, err = startUpload(path, mode, in.Mkdir); err != nil {
			return nil, err
		}
		f.uploads[key] = up
	} else if up == nil || up.target != path {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "no upload %q in progress for %s; start at offset 0", in.UploadID, path)
	} else if in.Offset != up.size {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "upload %q is at offset %d, not %d", in.UploadID, up.size, in.Offset)
	}

	if _, err := up.tmp.Write(data); err != nil {
		up.discard()
		delete(f.uploads, key)
		return nil, fsError(err)
	}
	up.size += int64(len(data))
	up.touched = time.Now()
	out := writeOutput{Path: path, Written: len(data), Size: up.size}
	if final {
		delete(f.uploads, key)
		if err := up.commit(); err != nil {
			return nil, err
		}
		out.Complete = true
	}
	return &gadget.Response{Output: out}, nil
}

func startUpload(target string, mode os.FileMode, mkdir bool) (*upload, error) {
	dir := filepath.Dir(target)
	if mkdir {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fsError(err)
		}
	}
	if st, err := os.Stat(target); err == nil {
		if st.IsDir() {
			return nil, protocol.Errorf(protocol.CodeInvalidInput, "%s is a directory", target)
		}
		if mode == 0 {
			mode = st.Mode().Perm()
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fsError(err)
	}
	if mode == 0 {
		mode = 0o644
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".vims-gadget-*")
	if err != nil {
		return nil, fsError(err)
	}
	return &upload{target: target, tmp: tmp, mode: mode, touched: time.Now()}, nil
}

func (u *upload) commit() error {
	name := u.tmp.Name()
	if err := u.tmp.Chmod(u.mode); err != nil {
		u.discard()
		return fsError(err)
	}
	if err := u.tmp.Sync(); err != nil {
		u.discard()
		return fsError(err)
	}
	if err := u.tmp.Close(); err != nil {
		os.Remove(name)
		return fsError(err)
	}
	if err := os.Rename(name, u.target); err != nil {
		os.Remove(name)
		return fsError(err)
	}
	if d, err := os.Open(filepath.Dir(u.target)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func (u *upload) discard() {
	name := u.tmp.Name()
	u.tmp.Close()
	os.Remove(name)
}

// expireLocked drops uploads nobody has written to for uploadIdleTime.
func (f *files) expireLocked(now time.Time) {
	for k, u := range f.uploads {
		if now.Sub(u.touched) > uploadIdleTime {
			u.discard()
			delete(f.uploads, k)
		}
	}
}

func parseMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0, nil
	}
	// Permission bits only: setuid/setgid files written remotely would hand
	// out the agent account's identity.
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n == 0 || n > 0o777 {
		return 0, protocol.Errorf(protocol.CodeInvalidInput, "mode %q is not octal permissions like 0644", s)
	}
	return os.FileMode(n), nil
}

func fsError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return protocol.Errorf(protocol.CodeInvalidInput, "%v", err)
	case errors.Is(err, fs.ErrPermission):
		return protocol.Errorf(protocol.CodeDenied, "%v", err)
	}
	return protocol.Errorf(protocol.CodeFailed, "%v", err)
}

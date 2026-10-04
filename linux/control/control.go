//go:build linux

// Package control is the agent's local control socket: the CLI and other
// programs on the machine pair the gadget, read its status and send the
// owner messages through it, with no credentials of their own. Access is
// the socket's file permissions (0660, the agent's account and group).
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
)

// Operations.
const (
	OpStatus = "status"
	OpPair   = "pair"
	OpUnpair = "unpair"
	OpSend   = "send"
)

const (
	maxRequest     = 64 << 10
	requestTimeout = 2 * time.Minute
)

// Request is one line of JSON from a client.
type Request struct {
	Op     string `json:"op"`
	URI    string `json:"uri,omitempty"`
	Text   string `json:"text,omitempty"`
	Thread string `json:"thread,omitempty"`
}

// Info describes the gadget for status replies.
type Info struct {
	Name     string `json:"name"`
	Model    string `json:"model,omitempty"`
	Platform string `json:"platform,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	Key      string `json:"key"`
}

// Response is one line of JSON back.
type Response struct {
	OK      bool                    `json:"ok"`
	Error   string                  `json:"error,omitempty"`
	Info    *Info                   `json:"info,omitempty"`
	Status  *gadget.Status          `json:"status,omitempty"`
	Pair    *gadget.PairResult      `json:"pair,omitempty"`
	Message *protocol.MessageOutput `json:"message,omitempty"`
}

// Device is what the control socket drives.
type Device interface {
	Status() gadget.Status
	Pair(ctx context.Context, uri string) (gadget.PairResult, error)
	Unpair() error
	SendMessage(ctx context.Context, text, thread string) (protocol.MessageOutput, error)
}

// Serve listens on path until ctx ends. A stale socket file from a crashed
// agent is replaced; a live one means another agent runs, which is an
// error.
func Serve(ctx context.Context, path string, dev Device, info Info) error {
	if err := claim(path); err != nil {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("control: listen %s: %w", path, err)
	}
	defer os.Remove(path)
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return fmt.Errorf("control: chmod %s: %w", path, err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("control: accept: %w", err)
		}
		go handle(ctx, c, dev, info)
	}
}

func claim(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		c.Close()
		return fmt.Errorf("control: another vims-gadget is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("control: remove stale %s: %w", path, err)
	}
	return nil
}

func handle(ctx context.Context, c net.Conn, dev Device, info Info) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(requestTimeout))
	line, err := bufio.NewReaderSize(c, maxRequest).ReadSlice('\n')
	var req Request
	var resp Response
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		resp.Error = fmt.Sprintf("request exceeds %d bytes", maxRequest)
	case err != nil:
		return
	case json.Unmarshal(line, &req) != nil:
		resp.Error = "request is not JSON"
	default:
		resp = dispatch(ctx, req, dev, info)
	}
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

func dispatch(ctx context.Context, req Request, dev Device, info Info) Response {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout-5*time.Second)
	defer cancel()
	switch req.Op {
	case OpStatus:
		st := dev.Status()
		return Response{OK: true, Info: &info, Status: &st}
	case OpPair:
		res, err := dev.Pair(ctx, req.URI)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{OK: true, Pair: &res}
	case OpUnpair:
		if err := dev.Unpair(); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{OK: true}
	case OpSend:
		out, err := dev.SendMessage(ctx, req.Text, req.Thread)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{OK: true, Message: &out}
	}
	return Response{Error: fmt.Sprintf("unknown op %q", req.Op)}
}

// Do sends one request to the agent listening on path.
func Do(ctx context.Context, path string, req Request) (Response, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Response{}, fmt.Errorf("cannot reach the vims-gadget service at %s (is it running?): %w", path, err)
	}
	defer c.Close()
	deadline := time.Now().Add(requestTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)
	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if _, err := c.Write(append(b, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return Response{}, fmt.Errorf("vims-gadget service did not answer: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("vims-gadget service answered garbage: %w", err)
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

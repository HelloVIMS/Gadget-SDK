//go:build linux

package commands

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
)

const (
	maxCommandLen    = 64 << 10
	maxStdinLen      = 1 << 20
	maxStreamCapture = 256 << 10
	defaultRunTime   = time.Minute
	maxRunTime       = 10 * time.Minute
)

type runInput struct {
	Command   string `json:"command"`
	Cwd       string `json:"cwd,omitempty"`
	Stdin     string `json:"stdin,omitempty"`
	TimeoutMS int64  `json:"timeout_ms,omitempty"`
}

type runOutput struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Truncated  bool   `json:"truncated,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// capped keeps the first max bytes written and counts the rest.
type capped struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	if room := c.max - c.buf.Len(); n > room {
		c.truncated = true
		p = p[:max(room, 0)]
	}
	c.buf.Write(p)
	return n, nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.ToValidUTF8(c.buf.String(), "\uFFFD")
}

func runCommand(home string) func(ctx context.Context, req *gadget.Request) (*gadget.Response, error) {
	return func(ctx context.Context, req *gadget.Request) (*gadget.Response, error) {
		var in runInput
		if err := req.Decode(&in); err != nil {
			return nil, err
		}
		if strings.TrimSpace(in.Command) == "" {
			return nil, protocol.Errorf(protocol.CodeInvalidInput, "command is required")
		}
		if len(in.Command) > maxCommandLen || len(in.Stdin) > maxStdinLen {
			return nil, protocol.Errorf(protocol.CodeTooLarge, "command or stdin too long")
		}
		limit := defaultRunTime
		if in.TimeoutMS > 0 {
			limit = min(time.Duration(in.TimeoutMS)*time.Millisecond, maxRunTime)
		}
		dir := home
		if in.Cwd != "" {
			var err error
			if dir, err = resolve(home, in.Cwd); err != nil {
				return nil, err
			}
			if st, err := os.Stat(dir); err != nil || !st.IsDir() {
				return nil, protocol.Errorf(protocol.CodeInvalidInput, "cwd %s is not a directory", dir)
			}
		}

		runCtx, cancel := context.WithTimeout(ctx, limit)
		defer cancel()
		cmd := exec.CommandContext(runCtx, "/bin/sh", "-c", in.Command)
		cmd.Dir = dir
		cmd.Env = os.Environ()
		// Own process group, so cancellation kills what the shell started.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = 2 * time.Second
		if in.Stdin != "" {
			cmd.Stdin = strings.NewReader(in.Stdin)
		}
		stdout, stderr := &capped{max: maxStreamCapture}, &capped{max: maxStreamCapture}
		cmd.Stdout, cmd.Stderr = stdout, stderr

		start := time.Now()
		err := cmd.Run()
		out := runOutput{
			Stdout:     stdout.String(),
			Stderr:     stderr.String(),
			Truncated:  stdout.truncated || stderr.truncated,
			DurationMS: time.Since(start).Milliseconds(),
		}
		var exitErr *exec.ExitError
		switch {
		case err == nil:
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case runCtx.Err() == context.DeadlineExceeded:
			out.TimedOut, out.ExitCode = true, -1
		case errors.As(err, &exitErr):
			out.ExitCode = exitErr.ExitCode()
		case errors.Is(err, exec.ErrWaitDelay):
			// The command exited; something it started kept the pipes open.
			out.ExitCode = cmd.ProcessState.ExitCode()
		default:
			return nil, protocol.Errorf(protocol.CodeFailed, "run: %v", err)
		}
		return &gadget.Response{Output: out}, nil
	}
}

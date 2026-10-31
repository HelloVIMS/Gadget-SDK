package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/hellovims/gadget-sdk/protocol"
	"os/exec"
	"strings"
	"time"
)

const maxOutput = 256 * 1024

type boundedOutput struct {
	buffer   bytes.Buffer // Do not embed: promoted ReadFrom would bypass the bound.
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.limit - w.buffer.Len()
	if n > remaining {
		w.overflow = true
		p = p[:remaining]
		w.cancel()
	}
	_, _ = w.buffer.Write(p)
	return n, nil
}

// No shell, command concatenation, prompt argv, credential extraction, or auto-retry.
func processRunner(binary string) runner {
	return func(ctx context.Context, args []string, stdin string) (json.RawMessage, error) {
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		stdout := &boundedOutput{limit: maxOutput, cancel: cancel}
		stderr := &boundedOutput{limit: 16 * 1024, cancel: cancel}
		cmd := exec.CommandContext(child, binary, args...)
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		cmd.WaitDelay = 2 * time.Second
		err := cmd.Run()
		if stdout.overflow || stderr.overflow {
			return nil, protocol.Errorf(protocol.CodeTooLarge, "T3 command exceeded its output limit; its submission outcome may be unknown")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return nil, protocol.Errorf(protocol.CodeUnavailable, "T3 exited with status %d; inspect its UI/logs locally", exit.ExitCode())
			}
			return nil, protocol.Errorf(protocol.CodeUnavailable, "could not execute the configured T3 CLI")
		}
		return append(json.RawMessage(nil), stdout.buffer.Bytes()...), nil
	}
}

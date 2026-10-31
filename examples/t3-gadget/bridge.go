// A deliberately small integration with T3 Code's supported local thread CLI.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxPrompt = 32 * 1024

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type config struct {
	Binary      string
	Project     string
	BaseRef     string
	StateDir    string
	AllowWrites bool
}
type runner func(context.Context, []string, string) (json.RawMessage, error)
type bridge struct {
	cfg      config
	run      runner
	receipts *receiptStore
}

func newBridge(cfg config) (*bridge, error) {
	if !filepath.IsAbs(cfg.Binary) {
		return nil, errors.New("-t3 must be an absolute path to the trusted T3 executable")
	}
	if info, err := os.Stat(cfg.Binary); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("-t3 must name a regular executable file")
	}
	if strings.TrimSpace(cfg.Project) == "" || strings.HasPrefix(cfg.Project, "-") || strings.ContainsAny(cfg.Project, "\x00\r\n") {
		return nil, errors.New("a fixed project id or absolute project path is required")
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return nil, errors.New("-state-dir must be absolute")
	}
	if cfg.BaseRef == "" {
		cfg.BaseRef = "HEAD"
	}
	if strings.ContainsAny(cfg.BaseRef, "\x00\r\n") {
		return nil, errors.New("invalid base ref")
	}
	receipts, err := newReceiptStore(filepath.Join(cfg.StateDir, "requests"))
	if err != nil {
		return nil, err
	}
	return &bridge{cfg: cfg, run: processRunner(cfg.Binary), receipts: receipts}, nil
}

type readInput struct {
	ThreadID string `json:"thread_id"`
	Messages *int   `json:"messages,omitempty"`
}
type startInput struct {
	RequestID string `json:"request_id"`
	Prompt    string `json:"prompt"`
}
type sendInput struct {
	RequestID string `json:"request_id"`
	ThreadID  string `json:"thread_id"`
	Prompt    string `json:"prompt"`
}
type requestInput struct {
	RequestID string `json:"request_id"`
}

func decode(req *gadget.Request, target any) error {
	raw := bytes.TrimSpace(req.Input)
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if len(req.Body) != 0 || len(raw) > 64*1024 || raw[0] != '{' {
		return protocol.Errorf(protocol.CodeInvalidInput, "expected a bounded JSON object without a binary body")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return protocol.Errorf(protocol.CodeInvalidInput, "invalid command input: %v", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return protocol.Errorf(protocol.CodeInvalidInput, "expected exactly one JSON object")
	}
	return nil
}
func (b *bridge) commands() []gadget.Command {
	commands := []gadget.Command{
		{Name: "t3.capabilities", Description: "Describe this bridge's explicit capabilities and limitations", Risk: protocol.RiskRead,
			Input: json.RawMessage(`{"type":"object","additionalProperties":false}`), Handler: b.capabilities},
		{Name: "t3.threads.list", Description: "List threads in the owner-configured T3 project", Risk: protocol.RiskRead,
			Input: json.RawMessage(`{"type":"object","additionalProperties":false}`), Handler: b.list},
		{Name: "t3.thread.read", Description: "Read a project thread's status and recent messages; does not wait for completion", Risk: protocol.RiskRead,
			Input: json.RawMessage(`{"type":"object","properties":{"thread_id":{"type":"string","minLength":1},"messages":{"type":"integer","minimum":1,"maximum":50}},"required":["thread_id"],"additionalProperties":false}`), Handler: b.read},
		{Name: "t3.request.read", Description: "Inspect a durable submission receipt, not the agent's completion status", Risk: protocol.RiskRead,
			Input: json.RawMessage(`{"type":"object","properties":{"request_id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"}},"required":["request_id"],"additionalProperties":false}`), Handler: b.request},
	}
	if b.cfg.AllowWrites {
		commands = append(commands,
			gadget.Command{Name: "t3.thread.start", Description: "Submit a coding task in a new worktree; reuse request_id only for the identical submission", Risk: protocol.RiskExec,
				Input: json.RawMessage(`{"type":"object","properties":{"request_id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},"prompt":{"type":"string","minLength":1,"maxLength":32768}},"required":["request_id","prompt"],"additionalProperties":false}`), Handler: b.start},
			gadget.Command{Name: "t3.thread.send", Description: "Queue a follow-up without interrupting a running thread; request_id suppresses replays", Risk: protocol.RiskExec,
				Input: json.RawMessage(`{"type":"object","properties":{"request_id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},"thread_id":{"type":"string","minLength":1},"prompt":{"type":"string","minLength":1,"maxLength":32768}},"required":["request_id","thread_id","prompt"],"additionalProperties":false}`), Handler: b.send},
		)
	}
	return commands
}
func (b *bridge) capabilities(_ context.Context, req *gadget.Request) (*gadget.Response, error) {
	if err := decode(req, &struct{}{}); err != nil {
		return nil, err
	}
	return &gadget.Response{Output: map[string]any{
		"project": b.cfg.Project, "writes_enabled": b.cfg.AllowWrites,
		"new_worktree_base": b.cfg.BaseRef, "queued_followups": b.cfg.AllowWrites,
		"submission_receipts": true, "stop_agent": false, "approve_requests": false,
		"native_fork": false, "remote_mcp_oauth": false,
		"model_and_permissions": "inherit T3 project defaults",
	}}, nil
}
func (b *bridge) invoke(ctx context.Context, args []string, stdin string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, err := b.run(ctx, args, stdin)
	if err != nil {
		return nil, err
	}
	if len(output) > maxOutput || !json.Valid(output) || bytes.Equal(bytes.TrimSpace(output), []byte("null")) {
		return nil, protocol.Errorf(protocol.CodeFailed, "T3 returned invalid or oversized JSON; check CLI/server compatibility")
	}
	return output, nil
}
func (b *bridge) list(ctx context.Context, req *gadget.Request) (*gadget.Response, error) {
	if err := decode(req, &struct{}{}); err != nil {
		return nil, err
	}
	data, err := b.listThreads(ctx)
	if err != nil {
		return nil, err
	}
	return &gadget.Response{Output: data}, nil
}
func (b *bridge) listThreads(ctx context.Context) (json.RawMessage, error) {
	data, err := b.invoke(ctx, []string{"thread", "list", "--project=" + b.cfg.Project, "--json"}, "")
	if err != nil {
		return nil, err
	}
	var threads []struct {
		ThreadID string `json:"threadId"`
	}
	if err := json.Unmarshal(data, &threads); err != nil {
		return nil, protocol.Errorf(protocol.CodeFailed, "unexpected T3 thread list")
	}
	for _, thread := range threads {
		if !validThreadID(thread.ThreadID) {
			return nil, protocol.Errorf(protocol.CodeFailed, "invalid thread id in T3 list")
		}
	}
	return data, nil
}
func validThreadID(id string) bool {
	return len(id) > 0 && strings.TrimSpace(id) == id && len(id) <= 512 && !strings.HasPrefix(id, "-") && !strings.ContainsAny(id, "\x00\r\n")
}
func (b *bridge) authorizeThread(ctx context.Context, id string) error {
	if !validThreadID(id) {
		return protocol.Errorf(protocol.CodeInvalidInput, "invalid thread_id")
	}
	data, err := b.listThreads(ctx)
	if err != nil {
		return err
	}
	var threads []struct {
		ThreadID string `json:"threadId"`
	}
	if err := json.Unmarshal(data, &threads); err != nil {
		return err
	}
	for _, thread := range threads {
		if thread.ThreadID == id {
			return nil
		}
	}
	return protocol.Errorf(protocol.CodeDenied, "thread is not in the configured project's top-level thread list")
}
func (b *bridge) read(ctx context.Context, req *gadget.Request) (*gadget.Response, error) {
	var in readInput
	if err := decode(req, &in); err != nil {
		return nil, err
	}
	messages := 10
	if in.Messages != nil {
		messages = *in.Messages
	}
	if messages < 1 || messages > 50 {
		return nil, protocol.Errorf(protocol.CodeInvalidInput, "messages must be between 1 and 50")
	}
	if err := b.authorizeThread(ctx, in.ThreadID); err != nil {
		return nil, err
	}
	data, err := b.invoke(ctx, []string{"thread", "show", in.ThreadID, fmt.Sprintf("--messages=%d", messages), "--json"}, "")
	if err != nil {
		return nil, err
	}
	var result struct {
		Thread struct {
			ThreadID string `json:"threadId"`
		} `json:"thread"`
	}
	if json.Unmarshal(data, &result) != nil || result.Thread.ThreadID != in.ThreadID {
		return nil, protocol.Errorf(protocol.CodeFailed, "unexpected T3 thread response")
	}
	return &gadget.Response{Output: data}, nil
}
func (b *bridge) request(_ context.Context, req *gadget.Request) (*gadget.Response, error) {
	var in requestInput
	if err := decode(req, &in); err != nil {
		return nil, err
	}
	receipt, err := b.receipts.read(in.RequestID)
	if err != nil {
		return nil, err
	}
	return &gadget.Response{Output: receipt}, nil
}
func validSubmission(id, prompt string) error {
	if !requestIDPattern.MatchString(id) {
		return protocol.Errorf(protocol.CodeInvalidInput, "invalid request_id")
	}
	if strings.TrimSpace(prompt) == "" || len(prompt) > maxPrompt || strings.ContainsRune(prompt, 0) {
		return protocol.Errorf(protocol.CodeInvalidInput, "prompt must be non-empty, at most 32768 bytes, and contain no NUL")
	}
	return nil
}
func (b *bridge) start(ctx context.Context, req *gadget.Request) (*gadget.Response, error) {
	if !b.cfg.AllowWrites {
		return nil, protocol.Errorf(protocol.CodeDenied, "writes are disabled")
	}
	var in startInput
	if err := decode(req, &in); err != nil {
		return nil, err
	}
	if err := validSubmission(in.RequestID, in.Prompt); err != nil {
		return nil, err
	}
	args := []string{"thread", "start", b.cfg.Project, "-", "--worktree=" + b.cfg.BaseRef, "--title=VIMS " + in.RequestID, "--json"}
	return b.submit(ctx, "start", in.RequestID, in, args, in.Prompt, "")
}
func (b *bridge) send(ctx context.Context, req *gadget.Request) (*gadget.Response, error) {
	if !b.cfg.AllowWrites {
		return nil, protocol.Errorf(protocol.CodeDenied, "writes are disabled")
	}
	var in sendInput
	if err := decode(req, &in); err != nil {
		return nil, err
	}
	if err := validSubmission(in.RequestID, in.Prompt); err != nil {
		return nil, err
	}
	if err := b.authorizeThread(ctx, in.ThreadID); err != nil {
		return nil, err
	}
	return b.submit(ctx, "send", in.RequestID, in, []string{"thread", "send", in.ThreadID, "-", "--json"}, in.Prompt, in.ThreadID)
}
func (b *bridge) submit(ctx context.Context, operation, id string, input any, args []string, prompt, expectedThread string) (*gadget.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(struct {
		Operation, Project, BaseRef string
		Input                       any
	}{operation, b.cfg.Project, b.cfg.BaseRef, input})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	receipt, fresh, err := b.receipts.reserve(id, operation, hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}
	if !fresh {
		if receipt.State == "accepted" {
			return &gadget.Response{Output: receipt.Result}, nil
		}
		return nil, protocol.Errorf(protocol.CodeUnavailable, "request %s is %s; inspect t3.request.read and T3 before taking further action; it will not be retried automatically", id, receipt.State)
	}
	data, err := b.invoke(ctx, args, prompt)
	if err == nil {
		var result struct {
			ThreadID string `json:"threadId"`
		}
		if json.Unmarshal(data, &result) != nil || !validThreadID(result.ThreadID) || (expectedThread != "" && result.ThreadID != expectedThread) {
			err = protocol.Errorf(protocol.CodeFailed, "unexpected T3 submission response")
		}
	}
	if err != nil {
		receipt.State = "unknown"
		_ = b.receipts.finish(receipt) // The original pending claim still prevents replay if this fails.
		return nil, fmt.Errorf("request %s has an uncertain submission outcome; inspect T3 before retrying: %w", id, err)
	}
	receipt.State = "accepted"
	receipt.Result = data
	if err := b.receipts.finish(receipt); err != nil {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "T3 accepted request %s but its receipt could not be durably confirmed; inspect T3 before retrying", id)
	}
	return &gadget.Response{Output: data}, nil
}

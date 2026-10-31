package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func testBridge(t *testing.T, writes bool) *bridge {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newBridge(config{Binary: executable, Project: "project-1", BaseRef: "main", StateDir: t.TempDir(), AllowWrites: writes})
	if err != nil {
		t.Fatal(err)
	}
	b.run = func(context.Context, []string, string) (json.RawMessage, error) {
		t.Error("unexpected CLI invocation")
		return nil, errors.New("unexpected invocation")
	}
	return b
}
func request(value any) *gadget.Request {
	data, _ := json.Marshal(value)
	return &gadget.Request{Input: data}
}
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var remote *protocol.RemoteError
	if !errors.As(err, &remote) || remote.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}
func TestReadOnlyCatalogAndRisk(t *testing.T) {
	b := testBridge(t, false)
	if len(b.commands()) != 4 {
		t.Fatal("read-only catalog includes mutations")
	}
	for _, cmd := range b.commands() {
		if cmd.Risk != protocol.RiskRead {
			t.Fatalf("unexpected risk for %s", cmd.Name)
		}
	}
	_, err := b.start(context.Background(), request(startInput{RequestID: "job-1", Prompt: "do work"}))
	requireCode(t, err, protocol.CodeDenied)
	b.cfg.AllowWrites = true
	cmds := b.commands()
	if len(cmds) != 6 || cmds[4].Risk != protocol.RiskExec || cmds[5].Risk != protocol.RiskExec {
		t.Fatal("mutation risk metadata incorrect")
	}
	store, err := gadget.NewFileStore(filepath.Join(t.TempDir(), "pairing"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gadget.New(gadget.Config{Name: "T3 test", Store: store, Commands: cmds}); err != nil {
		t.Fatal(err)
	}
	res, err := b.capabilities(context.Background(), request(struct{}{}))
	if err != nil || res.Output.(map[string]any)["stop_agent"] != false {
		t.Fatal("must not advertise unsupported stop")
	}
}
func TestStartUsesFixedProjectWorktreeAndLiteralStdin(t *testing.T) {
	b := testBridge(t, true)
	prompt := "--full-access $(touch /tmp/not-executed) \"quotes\"\nsecond line"
	b.run = func(_ context.Context, args []string, stdin string) (json.RawMessage, error) {
		want := []string{"thread", "start", "project-1", "-", "--worktree=main", "--title=VIMS job-1", "--json"}
		if !reflect.DeepEqual(args, want) || stdin != prompt {
			t.Fatalf("unexpected invocation: %#v, %q", args, stdin)
		}
		return json.RawMessage(`{"threadId":"thread-1","projectId":"project-1","runId":"run-1"}`), nil
	}
	res, err := b.start(context.Background(), request(startInput{RequestID: "job-1", Prompt: prompt}))
	if err != nil || !json.Valid(res.Output.(json.RawMessage)) {
		t.Fatalf("%v", err)
	}
	record, err := b.receipts.read("job-1")
	if err != nil || record.State != "accepted" {
		t.Fatalf("%+v %v", record, err)
	}
	content, err := os.ReadFile(filepath.Join(b.receipts.dir, "job-1.json"))
	if err != nil || strings.Contains(string(content), "touch /tmp") {
		t.Fatal("receipt must not retain prompts")
	}
}
func TestAcceptedSubmissionReplaysAcrossRestart(t *testing.T) {
	b := testBridge(t, true)
	var calls atomic.Int32
	b.run = func(context.Context, []string, string) (json.RawMessage, error) {
		calls.Add(1)
		return json.RawMessage(`{"threadId":"thread-1","runId":"run-1"}`), nil
	}
	in := request(startInput{RequestID: "repeat", Prompt: "original"})
	first, err := b.start(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.start(context.Background(), in)
	if err != nil || !reflect.DeepEqual(first, second) || calls.Load() != 1 {
		t.Fatal("duplicate submission", err)
	}
	restarted, err := newBridge(b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.run = b.run
	if _, err := restarted.start(context.Background(), in); err != nil || calls.Load() != 1 {
		t.Fatal("restart replayed submission", err)
	}
	_, err = restarted.start(context.Background(), request(startInput{RequestID: "repeat", Prompt: "different"}))
	requireCode(t, err, protocol.CodeInvalidInput)
	restarted.cfg.Project = "other-project"
	_, err = restarted.start(context.Background(), in)
	requireCode(t, err, protocol.CodeInvalidInput)
}
func TestUncertainSubmissionIsNeverAutomaticallyRetried(t *testing.T) {
	for _, mode := range []string{"exit", "malformed", "wrong-shape", "oversized", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			b := testBridge(t, true)
			calls := 0
			b.run = func(context.Context, []string, string) (json.RawMessage, error) {
				calls++
				switch mode {
				case "exit":
					return nil, errors.New("lost acknowledgement")
				case "malformed":
					return json.RawMessage(`not json`), nil
				case "wrong-shape":
					return json.RawMessage(`{"accepted":true}`), nil
				case "oversized":
					return json.RawMessage(strings.Repeat(" ", maxOutput+1)), nil
				default:
					return nil, context.Canceled
				}
			}
			in := request(startInput{RequestID: "uncertain", Prompt: "do work"})
			if _, err := b.start(context.Background(), in); err == nil {
				t.Fatal("expected uncertainty")
			}
			r, err := b.receipts.read("uncertain")
			if err != nil || r.State != "unknown" {
				t.Fatalf("%+v %v", r, err)
			}
			_, err = b.start(context.Background(), in)
			requireCode(t, err, protocol.CodeUnavailable)
			if calls != 1 {
				t.Fatal("retried uncertain submission")
			}
		})
	}
}
func TestConcurrentInstancesReserveOnlyOnce(t *testing.T) {
	b := testBridge(t, true)
	another, err := newBridge(b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	fn := func(context.Context, []string, string) (json.RawMessage, error) {
		calls.Add(1)
		close(entered)
		<-release
		return json.RawMessage(`{"threadId":"thread-1"}`), nil
	}
	b.run = fn
	another.run = fn
	done := make(chan error, 1)
	in := request(startInput{RequestID: "concurrent", Prompt: "only once"})
	go func() { _, err := b.start(context.Background(), in); done <- err }()
	<-entered
	_, err = another.start(context.Background(), in)
	requireCode(t, err, protocol.CodeUnavailable)
	if calls.Load() != 1 {
		t.Fatal("duplicate process")
	}
	// Cleanup waits for the worker after releasing its gate.
	t.Cleanup(func() {
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}
func TestReadAndSendRequireProjectMembership(t *testing.T) {
	b := testBridge(t, true)
	var invocations [][]string
	b.run = func(_ context.Context, args []string, stdin string) (json.RawMessage, error) {
		invocations = append(invocations, args)
		switch args[1] {
		case "list":
			return json.RawMessage(`[{"threadId":"allowed"}]`), nil
		case "show":
			return json.RawMessage(`{"thread":{"threadId":"allowed","status":"waiting","pendingRequestCount":1},"messages":[]}`), nil
		case "send":
			if !reflect.DeepEqual(args, []string{"thread", "send", "allowed", "-", "--json"}) || stdin != "follow up" {
				t.Fatal("unexpected send invocation")
			}
			return json.RawMessage(`{"threadId":"allowed","runId":"next-run","delivery":"queued"}`), nil
		default:
			t.Fatal("unexpected command")
			return nil, nil
		}
	}
	_, err := b.read(context.Background(), request(readInput{ThreadID: "outside"}))
	requireCode(t, err, protocol.CodeDenied)
	_, err = b.send(context.Background(), request(sendInput{RequestID: "denied", ThreadID: "outside", Prompt: "no"}))
	requireCode(t, err, protocol.CodeDenied)
	if len(invocations) != 2 || invocations[0][1] != "list" || invocations[1][1] != "list" {
		t.Fatal("out-of-project access escaped membership check")
	}
	res, err := b.read(context.Background(), request(readInput{ThreadID: "allowed"}))
	if err != nil || !strings.Contains(string(res.Output.(json.RawMessage)), `"waiting"`) {
		t.Fatal("lost waiting state", err)
	}
	if _, err = b.send(context.Background(), request(sendInput{RequestID: "follow-up", ThreadID: "allowed", Prompt: "follow up"})); err != nil {
		t.Fatal(err)
	}
}
func TestStrictInputValidation(t *testing.T) {
	cases := []string{
		`null`, `[]`, `{} {}`, `{"request_id":"a","prompt":"x","shell":"sh"}`,
		`{"request_id":"../escape","prompt":"x"}`, `{"request_id":"a","prompt":" "}`,
		`{"request_id":"a","prompt":"\u0000"}`,
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			b := testBridge(t, true)
			_, err := b.start(context.Background(), &gadget.Request{Input: json.RawMessage(input)})
			requireCode(t, err, protocol.CodeInvalidInput)
		})
	}
	b := testBridge(t, true)
	_, err := b.start(context.Background(), request(startInput{RequestID: "big", Prompt: strings.Repeat("x", maxPrompt+1)}))
	requireCode(t, err, protocol.CodeInvalidInput)
	zero := 0
	_, err = b.read(context.Background(), request(readInput{ThreadID: "id", Messages: &zero}))
	requireCode(t, err, protocol.CodeInvalidInput)
	_, err = b.list(context.Background(), &gadget.Request{Body: []byte("unexpected")})
	requireCode(t, err, protocol.CodeInvalidInput)
}
func TestCorruptReceiptFailsClosed(t *testing.T) {
	b := testBridge(t, true)
	if err := os.WriteFile(filepath.Join(b.receipts.dir, "broken.json"), []byte(`{"state":`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := b.start(context.Background(), request(startInput{RequestID: "broken", Prompt: "never launch"}))
	requireCode(t, err, protocol.CodeUnavailable)
}
func TestCanceledInputDoesNotReserveOrLaunch(t *testing.T) {
	b := testBridge(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.start(ctx, request(startInput{RequestID: "canceled", Prompt: "never launch"}))
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.receipts.dir, "canceled.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created a claim for an already-cancelled request")
	}
}

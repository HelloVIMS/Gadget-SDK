package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hellovims/gadget-sdk/protocol"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCLIProcessHelper(t *testing.T) {
	mode := os.Getenv("VIMS_T3_TEST_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		stdin, _ := io.ReadAll(os.Stdin)
		args := os.Args
		for i, arg := range args {
			if arg == "--" {
				args = args[i+1:]
				break
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"stdin": string(stdin), "args": args})
	case "fail":
		fmt.Fprintln(os.Stderr, "secret-credential-must-not-be-returned")
		os.Exit(2)
	case "large":
		fmt.Fprint(os.Stdout, strings.Repeat("x", maxOutput+1))
	case "large-stderr":
		fmt.Fprint(os.Stderr, strings.Repeat("x", 16*1024+1))
	case "wait":
		time.Sleep(30 * time.Second)
	default:
		os.Exit(3)
	}
	os.Exit(0)
}
func helperRunner(t *testing.T, mode string) runner {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VIMS_T3_TEST_HELPER", mode)
	return processRunner(binary)
}
func helperArgs(extra ...string) []string {
	return append([]string{"-test.run=^TestCLIProcessHelper$", "--"}, extra...)
}
func TestProcessRunnerPreservesLiteralArgumentsAndStdin(t *testing.T) {
	run := helperRunner(t, "echo")
	args := []string{"--json", "a b", "$(not-a-shell)", "semi;colon"}
	out, err := run(context.Background(), helperArgs(args...), "private prompt\n--not-a-flag")
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Stdin string   `json:"stdin"`
		Args  []string `json:"args"`
	}
	if err := json.Unmarshal(out, &value); err != nil {
		t.Fatal(err)
	}
	if value.Stdin != "private prompt\n--not-a-flag" || !reflect.DeepEqual(value.Args, args) {
		t.Fatalf("%+v", value)
	}
}
func TestProcessRunnerBoundsBothOutputStreams(t *testing.T) {
	for _, mode := range []string{"large", "large-stderr"} {
		t.Run(mode, func(t *testing.T) {
			run := helperRunner(t, mode)
			_, err := run(context.Background(), helperArgs(), "")
			requireCode(t, err, protocol.CodeTooLarge)
		})
	}
}
func TestProcessRunnerDoesNotExposeStderr(t *testing.T) {
	run := helperRunner(t, "fail")
	_, err := run(context.Background(), helperArgs(), "")
	requireCode(t, err, protocol.CodeUnavailable)
	if strings.Contains(err.Error(), "secret-credential") {
		t.Fatal("stderr leaked")
	}
}
func TestProcessRunnerHonorsCancellation(t *testing.T) {
	run := helperRunner(t, "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := run(ctx, helperArgs(), "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

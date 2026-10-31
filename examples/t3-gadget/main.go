// t3-gadget exposes a bounded, opt-in T3 Code integration over VGP.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func run() error {
	var cfg config
	var pairStdin bool
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	flag.StringVar(&cfg.Binary, "t3", "", "absolute path to the trusted T3 executable")
	flag.StringVar(&cfg.Project, "project", "", "one registered T3 project id or absolute root path")
	flag.StringVar(&cfg.BaseRef, "base-ref", "HEAD", "base ref for every new, isolated T3 worktree")
	flag.StringVar(&cfg.StateDir, "state-dir", filepath.Join(configDir, "vims", "t3-gadget"), "private pairing and request-receipt directory")
	flag.BoolVar(&cfg.AllowWrites, "allow-writes", false, "explicitly enable task submission and queued follow-ups")
	flag.BoolVar(&pairStdin, "pair-stdin", false, "read one VIMS pairing URI from stdin (up to 16 KiB), then run")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	b, err := newBridge(cfg)
	if err != nil {
		return err
	}
	store, err := gadget.NewFileStore(filepath.Join(cfg.StateDir, "pairing"))
	if err != nil {
		return err
	}
	limits := protocol.DefaultLimits
	limits.MaxCalls = 4
	dev, err := gadget.New(gadget.Config{
		Name: "T3 Code bridge", Model: "t3-cli-example", Store: store, Commands: b.commands(), Limits: limits,
		OnStatus: func(status gadget.Status) { log.Printf("gadget: %s", status.State) },
	})
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- dev.Run(ctx) }()
	if pairStdin {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 16*1024+1))
		if err != nil {
			return err
		}
		if len(raw) > 16*1024 {
			return errors.New("pairing URI exceeds 16 KiB")
		}
		pairCtx, stop := context.WithTimeout(ctx, 2*time.Minute)
		result, err := dev.Pair(pairCtx, strings.TrimSpace(string(raw)))
		stop()
		if err != nil {
			return err
		}
		fmt.Printf("Paired. Compare this verification code with VIMS: %s\n", result.SAS)
	}
	err = <-done
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

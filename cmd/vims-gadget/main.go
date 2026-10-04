//go:build linux

// vims-gadget turns a Linux machine (a Raspberry Pi, any box) into a VIMS
// gadget: VIMS can run commands, move files and check health on it, and
// programs on it can send the owner messages.
//
//	sudo vims-gadget install --pair 'vimsgadget1:…'   install the service and pair
//	vims-gadget pair 'vimsgadget1:…'                  pair (again) with VIMS
//	vims-gadget status                                id, host and connection state
//	vims-gadget send-user-msg [--session-id ID] text  message the owner
//	vims-gadget unpair                                forget the host
//	sudo vims-gadget uninstall [--purge]              remove the service
//	vims-gadget run                                   the service itself
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/linux/commands"
	"github.com/hellovims/gadget-sdk/linux/control"
	"github.com/hellovims/gadget-sdk/linux/service"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "0.1.0"

const usage = `vims-gadget %s — make this machine a VIMS gadget

Usage:
  sudo vims-gadget install [--user NAME] [--name NAME] [--pair URI] [--yes]
  vims-gadget pair URI
  vims-gadget status
  vims-gadget send-user-msg [--session-id ID] TEXT
  vims-gadget unpair
  sudo vims-gadget uninstall [--purge]
  vims-gadget run [--state-dir DIR] [--socket PATH] [--name NAME]
  vims-gadget version

Get a pairing URI in VIMS: Settings → Devices → Add device.
The socket defaults to $VIMS_GADGET_SOCKET or %s.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version, service.Socket)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = runAgent(args)
	case "pair":
		err = pairCmd(args)
	case "status", "info":
		err = statusCmd(args)
	case "send-user-msg", "send":
		err = sendCmd(args)
	case "unpair":
		err = unpairCmd(args)
	case "install":
		err = installCmd(args)
	case "uninstall":
		err = uninstallCmd(args)
	case "version", "--version", "-v":
		fmt.Println("vims-gadget", version)
	case "help", "--help", "-h":
		fmt.Printf(usage, version, service.Socket)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, version, service.Socket)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vims-gadget:", err)
		os.Exit(1)
	}
}

func defaultSocket() string {
	if s := os.Getenv("VIMS_GADGET_SOCKET"); s != "" {
		return s
	}
	return service.Socket
}

func socketFlag(fs *flag.FlagSet) *string {
	return fs.String("socket", defaultSocket(), "control socket of the running service")
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", envOr("VIMS_GADGET_STATE_DIR", service.StateDir), "where the gadget's key and pairing live")
	socket := socketFlag(fs)
	host, _ := os.Hostname()
	name := fs.String("name", host, "how the gadget introduces itself to VIMS")
	verbose := fs.Bool("verbose", false, "log debug detail")
	fs.Parse(args)

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	store, err := gadget.NewFileStore(*stateDir)
	if err != nil {
		return err
	}
	firmware := "vims-gadget " + version
	model := detectModel()
	platform := runtime.GOOS + "/" + runtime.GOARCH
	dev, err := gadget.New(gadget.Config{
		Name:     *name,
		Model:    model,
		Platform: platform,
		Firmware: firmware,
		Commands: commands.All(commands.Options{Agent: firmware}),
		Store:    store,
		Logger:   log,
		OnStatus: func(s gadget.Status) {
			log.Info("status", "state", s.State, "host", s.Host, "addr", s.Addr, "err", s.LastError)
		},
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctlErr := make(chan error, 1)
	go func() {
		ctlErr <- control.Serve(ctx, *socket, dev, control.Info{Name: *name, Model: model, Platform: platform, Firmware: firmware, Key: dev.PublicKey().String()})
	}()
	log.Info("vims-gadget started", "id", dev.ID(), "name", *name, "state_dir", *stateDir, "socket", *socket)
	runErr := make(chan error, 1)
	go func() { runErr <- dev.Run(ctx) }()
	select {
	case err := <-ctlErr:
		stop()
		<-runErr
		if err != nil {
			return err
		}
		return nil
	case err := <-runErr:
		stop()
		<-ctlErr
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

func pairCmd(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	socket := socketFlag(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: vims-gadget pair URI (from VIMS: Settings → Devices → Add device)")
	}
	return pairVia(*socket, fs.Arg(0))
}

func pairVia(socket, uri string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	resp, err := control.Do(ctx, socket, control.Request{Op: control.OpPair, URI: uri})
	if err != nil {
		return err
	}
	p := resp.Pair
	fmt.Printf("Paired with %s as %s.\nCheck that VIMS shows the same code for this device: %s\n", p.Host, p.ID, p.SAS)
	return nil
}

func statusCmd(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	socket := socketFlag(fs)
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := control.Do(ctx, *socket, control.Request{Op: control.OpStatus})
	if err != nil {
		return err
	}
	st, info := resp.Status, resp.Info
	fmt.Printf("name:     %s\nid:       %s\nstate:    %s (since %s)\n", info.Name, st.ID, st.State, st.Since.Local().Format(time.DateTime))
	if st.Host != "" {
		fmt.Printf("host:     %s\n", st.Host)
	}
	if st.Addr != "" {
		fmt.Printf("address:  %s\n", st.Addr)
	}
	if st.LastError != "" {
		fmt.Printf("error:    %s\n", st.LastError)
	}
	fmt.Printf("model:    %s\nplatform: %s\nagent:    %s\nkey:      %s\n", info.Model, info.Platform, info.Firmware, info.Key)
	return nil
}

func sendCmd(args []string) error {
	fs := flag.NewFlagSet("send-user-msg", flag.ExitOnError)
	socket := socketFlag(fs)
	thread := fs.String("session-id", "", "post into a side conversation; reuse the id to keep later messages there")
	fs.Parse(args)
	text := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if text == "" {
		return errors.New(`usage: vims-gadget send-user-msg [--session-id ID] "text"`)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := control.Do(ctx, *socket, control.Request{Op: control.OpSend, Text: text, Thread: *thread})
	return err
}

func unpairCmd(args []string) error {
	fs := flag.NewFlagSet("unpair", flag.ExitOnError)
	socket := socketFlag(fs)
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := control.Do(ctx, *socket, control.Request{Op: control.OpUnpair}); err != nil {
		return err
	}
	fmt.Println("Unpaired. Remove the device in VIMS too (Settings → Devices).")
	return nil
}

func installCmd(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	account := fs.String("user", invokingUser(), "account VIMS runs commands as")
	host, _ := os.Hostname()
	name := fs.String("name", host, "how the gadget introduces itself to VIMS")
	uri := fs.String("pair", "", "pair with this URI once installed")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.Parse(args)
	a, err := service.LookupAccount(*account)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := service.Install(service.Options{Account: a, Name: *name, Source: self, Yes: *yes, In: os.Stdin, Out: os.Stdout}); err != nil {
		return err
	}
	if *uri == "" {
		fmt.Printf("Pair it: vims-gadget pair 'vimsgadget1:…' (VIMS: Settings → Devices → Add device)\n")
		return nil
	}
	if err := waitForSocket(service.Socket, 20*time.Second); err != nil {
		return err
	}
	return pairVia(service.Socket, *uri)
}

func uninstallCmd(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also delete the gadget's key and pairing")
	fs.Parse(args)
	return service.Uninstall(*purge, os.Stdout)
}

func waitForSocket(path string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := control.Do(ctx, path, control.Request{Op: control.OpStatus})
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the service did not come up (journalctl -u %s): %w", service.UnitName, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// invokingUser is the account that ran sudo, else the current one.
func invokingUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "root"
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// detectModel names the hardware: the device tree model on boards like the
// Raspberry Pi, else DMI vendor and product.
func detectModel() string {
	if b, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		if m := strings.TrimSpace(string(bytes.TrimRight(b, "\x00"))); m != "" {
			return truncate(m, 128)
		}
	}
	vendor, _ := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	product, _ := os.ReadFile("/sys/class/dmi/id/product_name")
	if m := strings.TrimSpace(strings.TrimSpace(string(vendor)) + " " + strings.TrimSpace(string(product))); m != "" {
		return truncate(m, 128)
	}
	return "Linux computer"
}

// truncate shortens s to n characters and blanks control characters, which
// a HELLO may not carry.
func truncate(s string, n int) string {
	r := []rune(s)
	for i, c := range r {
		if c < 0x20 || c == 0x7f {
			r[i] = ' '
		}
	}
	if len(r) > n {
		r = r[:n]
	}
	return strings.TrimSpace(string(r))
}

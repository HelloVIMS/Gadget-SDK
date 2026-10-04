//go:build linux

// Package service installs the agent as a systemd service.
package service

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// Install locations.
const (
	Binary     = "/usr/local/bin/vims-gadget"
	UnitName   = "vims-gadget.service"
	UnitPath   = "/etc/systemd/system/" + UnitName
	StateDir   = "/var/lib/vims-gadget"
	RuntimeDir = "/run/vims-gadget"
	Socket     = RuntimeDir + "/control.sock"
)

// Account is the user the agent runs as.
type Account struct {
	Name    string
	Group   string
	Home    string
	CanSudo bool
}

// LookupAccount resolves name and whether it can use sudo (member of sudo,
// wheel or admin).
func LookupAccount(name string) (Account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return Account{}, fmt.Errorf("no account %q: %w", name, err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		return Account{}, fmt.Errorf("account %q: primary group: %w", name, err)
	}
	a := Account{Name: u.Username, Group: g.Name, Home: u.HomeDir}
	if u.Uid == "0" {
		a.CanSudo = true
	}
	ids, _ := u.GroupIds()
	for _, id := range ids {
		if grp, err := user.LookupGroupId(id); err == nil && slices.Contains([]string{"sudo", "wheel", "admin"}, grp.Name) {
			a.CanSudo = true
		}
	}
	return a, nil
}

// Unit renders the systemd unit for a, with the gadget called name.
func Unit(a Account, name string) (string, error) {
	if name == "" || utf8.RuneCountInString(name) > 64 {
		return "", errors.New("gadget name must be 1-64 characters")
	}
	quoted, err := systemdQuote(name, true)
	if err != nil {
		return "", err
	}
	home, err := systemdQuote("HOME="+a.Home, false)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`[Unit]
Description=VIMS gadget agent
Documentation=https://github.com/HelloVIMS/gadget-sdk/tree/main/linux
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
Group=%s
Environment=%s
WorkingDirectory=%s
ExecStart=%s run --state-dir %s --socket %s --name %s
Restart=always
RestartSec=3
StateDirectory=vims-gadget
StateDirectoryMode=0700
RuntimeDirectory=vims-gadget
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
`, a.Name, a.Group, home, strings.ReplaceAll(a.Home, "%", "%%"), Binary, StateDir, Socket, quoted), nil
}

// systemdQuote quotes s as one systemd value: double quotes, backslash and
// quote escaped, the specifier % doubled, and — in command lines, where
// systemd expands variables — $ doubled.
func systemdQuote(s string, execArg bool) (string, error) {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			return "", fmt.Errorf("%q contains control characters", s)
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '%':
			b.WriteString("%%")
		case r == '$' && execArg:
			b.WriteString("$$")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// Options for Install.
type Options struct {
	Account Account
	Name    string
	// Source is the binary to install; usually os.Executable().
	Source string
	// Yes skips the confirmation prompt.
	Yes bool
	In  io.Reader
	Out io.Writer
}

// Install copies the binary, writes the unit and starts the service. It
// asks before giving VIMS the account unless Yes.
func Install(o Options) error {
	if os.Geteuid() != 0 {
		return errors.New("install needs root: run it with sudo")
	}
	fmt.Fprintf(o.Out, "VIMS will run commands on this machine as %q.\n", o.Account.Name)
	if o.Account.CanSudo {
		fmt.Fprintf(o.Out, "%q can use sudo, so VIMS will be able to as well. Use --user to choose an account without sudo.\n", o.Account.Name)
	} else {
		fmt.Fprintf(o.Out, "%q cannot use sudo.\n", o.Account.Name)
	}
	if !o.Yes && !confirm(o.In, o.Out, "Continue? [y/N] ") {
		return errors.New("not installed")
	}
	unit, err := Unit(o.Account, o.Name)
	if err != nil {
		return err
	}
	if err := copyBinary(o.Source, Binary); err != nil {
		return err
	}
	if err := writeFile(UnitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", UnitName); err != nil {
		return err
	}
	if err := systemctl("restart", UnitName); err != nil {
		return err
	}
	fmt.Fprintf(o.Out, "Installed %s and started %s.\n", Binary, UnitName)
	return nil
}

// Uninstall stops and removes the service and binary; purge also deletes
// the state (the gadget's key and pairing).
func Uninstall(purge bool, out io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall needs root: run it with sudo")
	}
	if _, err := os.Stat(UnitPath); err == nil {
		if err := systemctl("disable", "--now", UnitName); err != nil {
			return err
		}
		if err := os.Remove(UnitPath); err != nil {
			return err
		}
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
	}
	if err := os.Remove(Binary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if purge {
		if err := os.RemoveAll(StateDir); err != nil {
			return err
		}
		fmt.Fprintf(out, "Removed %s, %s and %s (this gadget's key and pairing).\n", UnitName, Binary, StateDir)
		return nil
	}
	fmt.Fprintf(out, "Removed %s and %s. The gadget's key and pairing stay in %s (--purge removes them).\n", UnitName, Binary, StateDir)
	return nil
}

func confirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyBinary(src, dst string) error {
	if same, _ := sameFile(src, dst); same {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	return writeFile(dst, data, 0o755)
}

func sameFile(a, b string) (bool, error) {
	sa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	sb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(sa, sb), nil
}

// writeFile replaces path atomically.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

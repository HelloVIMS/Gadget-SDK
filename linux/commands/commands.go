//go:build linux

// Package commands is the Linux gadget's command set: shell, files and
// health. Commands run as the account the agent runs as, with exactly its
// permissions.
package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/hellovims/gadget-sdk/gadget"
	"github.com/hellovims/gadget-sdk/protocol"
)

// Options configure the command set.
type Options struct {
	// Agent is the agent's name and version, reported by device.health.
	Agent string
	// Home is where relative paths and commands start; defaults to the
	// account's home directory.
	Home string
}

// All returns system.run, file.read, file.write and device.health.
func All(opts Options) []gadget.Command {
	if opts.Home == "" {
		opts.Home = homeDir()
	}
	files := newFiles(opts.Home)
	return []gadget.Command{
		{
			Name:        "system.run",
			Description: "Runs a shell command (/bin/sh -c) on this machine as the agent's account and returns its exit code, stdout and stderr (each capped at 256 KiB). Starts in the account's home directory unless cwd is given.",
			Risk:        protocol.RiskExec,
			Input:       schema(`{"type":"object","properties":{"command":{"type":"string","description":"Shell command line"},"cwd":{"type":"string","description":"Working directory"},"stdin":{"type":"string","description":"Text fed to the command's standard input"},"timeout_ms":{"type":"integer","minimum":1,"maximum":600000,"description":"Kill the command after this long (default 60000)"}},"required":["command"],"additionalProperties":false}`),
			Handler:     runCommand(opts.Home),
		},
		{
			Name:        "file.read",
			Description: "Reads up to 64 KiB of a file starting at offset; the bytes are the result body. Repeat with offset += length until eof. Relative paths and ~ start at the account's home directory.",
			Risk:        protocol.RiskRead,
			Input:       schema(`{"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer","minimum":0},"length":{"type":"integer","minimum":1,"maximum":65536}},"required":["path"],"additionalProperties":false}`),
			Handler:     files.read,
		},
		{
			Name:        "file.write",
			Description: "Writes a file, replacing it only once complete. Small files: pass content (text) or the body in one call. Large files: send chunks of at most 1 MiB with the same upload_id at increasing offsets and final=true on the last.",
			Risk:        protocol.RiskWrite,
			Input:       schema(`{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string","description":"Text to write when no body is sent"},"offset":{"type":"integer","minimum":0},"final":{"type":"boolean","description":"Last chunk (default true)"},"upload_id":{"type":"string","description":"Groups the chunks of one upload"},"mode":{"type":"string","description":"Octal permissions for a new file, e.g. 0644"},"mkdir":{"type":"boolean","description":"Create missing parent directories"}},"required":["path"],"additionalProperties":false}`),
			Handler:     files.write,
		},
		{
			Name:        "device.health",
			Description: "Reports hostname, OS, kernel, uptime, load, memory, disk space and temperature.",
			Risk:        protocol.RiskRead,
			Input:       schema(`{"type":"object","properties":{},"additionalProperties":false}`),
			Handler:     healthCommand(opts),
		},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "/"
}

// resolve expands ~ and makes p absolute against home.
func resolve(home, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", protocol.Errorf(protocol.CodeInvalidInput, "path is required")
	}
	if strings.ContainsRune(p, 0) {
		return "", protocol.Errorf(protocol.CodeInvalidInput, "path contains a NUL byte")
	}
	switch {
	case p == "~":
		p = home
	case strings.HasPrefix(p, "~/"):
		p = filepath.Join(home, p[2:])
	case !filepath.IsAbs(p):
		p = filepath.Join(home, p)
	}
	return filepath.Clean(p), nil
}

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// Limits are what a side can receive (PROTOCOL.md §5).
type Limits struct {
	MaxChunk   int `json:"max_chunk"`
	MaxMessage int `json:"max_message"`
	MaxCalls   int `json:"max_calls"`
}

// Limit bounds.
const (
	MinChunk         = 1024
	MinMessage       = 16 << 10
	MaxMessageLimit  = 64 << 20
	MaxCallsLimit    = 64
	MaxHelloSize     = 256 << 10
	maxHandshakeBody = 1024
	maxCommands      = 64
	maxCommandName   = 64
	maxDescription   = 512
	maxSchemaBytes   = 8 << 10
	maxCapsBytes     = 8 << 10
	maxNameLen       = 64
	maxMetaLen       = 128
)

// DefaultLimits suit a host or a Linux gadget.
var DefaultLimits = Limits{MaxChunk: MaxTransportMessage, MaxMessage: 16 << 20, MaxCalls: 8}

// preWelcomeLimits apply before the peer announced its own.
var preWelcomeLimits = Limits{MaxChunk: MaxTransportMessage, MaxMessage: MaxHelloSize, MaxCalls: 1}

// Validate checks the limits are in range.
func (l Limits) Validate() error {
	switch {
	case l.MaxChunk < MinChunk || l.MaxChunk > MaxTransportMessage:
		return fmt.Errorf("vgp: max_chunk %d outside %d-%d", l.MaxChunk, MinChunk, MaxTransportMessage)
	case l.MaxMessage < MinMessage || l.MaxMessage > MaxMessageLimit:
		return fmt.Errorf("vgp: max_message %d outside %d-%d", l.MaxMessage, MinMessage, MaxMessageLimit)
	case l.MaxCalls < 1 || l.MaxCalls > MaxCallsLimit:
		return fmt.Errorf("vgp: max_calls %d outside 1-%d", l.MaxCalls, MaxCallsLimit)
	}
	return nil
}

// Risk is what running a command can do (PROTOCOL.md §6).
type Risk string

// Risks.
const (
	RiskRead  Risk = "read"
	RiskWrite Risk = "write"
	RiskExec  Risk = "exec"
)

// Normalize maps unknown risks to exec, the most restrictive.
func (r Risk) Normalize() Risk {
	switch r {
	case RiskRead, RiskWrite, RiskExec:
		return r
	}
	return RiskExec
}

// CommandInfo describes a command a gadget offers.
type CommandInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Risk        Risk            `json:"risk"`
	Input       json.RawMessage `json:"input,omitempty"`
}

var commandNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// ValidCommandName reports whether name is a valid command or service name.
func ValidCommandName(name string) bool {
	return len(name) <= maxCommandName && commandNamePattern.MatchString(name)
}

// Validate checks a descriptor against PROTOCOL.md §6.
func (c CommandInfo) Validate() error {
	if !ValidCommandName(c.Name) {
		return fmt.Errorf("vgp: invalid command name %q", c.Name)
	}
	if utf8.RuneCountInString(c.Description) > maxDescription || !utf8.ValidString(c.Description) {
		return fmt.Errorf("vgp: command %s: description too long", c.Name)
	}
	if len(c.Input) > 0 {
		if len(c.Input) > maxSchemaBytes {
			return fmt.Errorf("vgp: command %s: input schema exceeds %d bytes", c.Name, maxSchemaBytes)
		}
		if !isJSONObject(c.Input) {
			return fmt.Errorf("vgp: command %s: input schema is not a JSON object", c.Name)
		}
	}
	return nil
}

// Hello is the gadget's first frame (PROTOCOL.md §6).
type Hello struct {
	Name     string          `json:"name"`
	Model    string          `json:"model,omitempty"`
	Platform string          `json:"platform,omitempty"`
	Firmware string          `json:"firmware,omitempty"`
	Commands []CommandInfo   `json:"commands,omitempty"`
	Caps     json.RawMessage `json:"caps,omitempty"`
	Limits
}

// Validate checks a HELLO. Unknown risks are normalised to exec.
func (h *Hello) Validate() error {
	if h.Name == "" || utf8.RuneCountInString(h.Name) > maxNameLen || !printable(h.Name) {
		return fmt.Errorf("vgp: name must be 1-%d printable characters", maxNameLen)
	}
	for field, v := range map[string]string{"model": h.Model, "platform": h.Platform, "firmware": h.Firmware} {
		if utf8.RuneCountInString(v) > maxMetaLen || !printable(v) {
			return fmt.Errorf("vgp: %s must be at most %d printable characters", field, maxMetaLen)
		}
	}
	if len(h.Commands) > maxCommands {
		return fmt.Errorf("vgp: at most %d commands", maxCommands)
	}
	seen := make(map[string]bool, len(h.Commands))
	for i := range h.Commands {
		c := &h.Commands[i]
		if err := c.Validate(); err != nil {
			return err
		}
		if seen[c.Name] {
			return fmt.Errorf("vgp: command %s listed twice", c.Name)
		}
		seen[c.Name] = true
		c.Risk = c.Risk.Normalize()
	}
	if len(h.Caps) > 0 {
		if len(h.Caps) > maxCapsBytes {
			return fmt.Errorf("vgp: caps exceed %d bytes", maxCapsBytes)
		}
		if !isJSONObject(h.Caps) {
			return fmt.Errorf("vgp: caps is not a JSON object")
		}
		h.Caps = json.RawMessage(bytes.TrimSpace(h.Caps))
	}
	return h.Limits.Validate()
}

// Command returns the descriptor named name.
func (h *Hello) Command(name string) (CommandInfo, bool) {
	for _, c := range h.Commands {
		if c.Name == name {
			return c, true
		}
	}
	return CommandInfo{}, false
}

// Welcome is the host's reply to HELLO (PROTOCOL.md §6).
type Welcome struct {
	ID       string   `json:"id"`
	Host     string   `json:"host,omitempty"`
	Time     int64    `json:"time"`
	Addrs    []string `json:"addrs,omitempty"`
	Services []string `json:"services,omitempty"`
	Limits
}

// Validate checks a WELCOME.
func (w *Welcome) Validate() error {
	if !ValidDeviceID(w.ID) {
		return fmt.Errorf("vgp: WELCOME carries an invalid id %q", w.ID)
	}
	if len(w.Addrs) > MaxPairingAddrs {
		return fmt.Errorf("vgp: WELCOME lists more than %d addresses", MaxPairingAddrs)
	}
	for _, a := range w.Addrs {
		if err := ValidateAddr(a); err != nil {
			return err
		}
	}
	return w.Limits.Validate()
}

// CallHeader is the header of a CALL frame.
type CallHeader struct {
	Command   string          `json:"cmd"`
	Input     json.RawMessage `json:"input,omitempty"`
	TimeoutMS int64           `json:"timeout_ms,omitempty"`
}

// ResultHeader is the header of a RESULT frame.
type ResultHeader struct {
	OK     bool            `json:"ok"`
	Output json.RawMessage `json:"output,omitempty"`
	Error  *RemoteError    `json:"error,omitempty"`
}

// EventHeader is the header of an EVENT frame.
type EventHeader struct {
	Name string          `json:"name"`
	Data json.RawMessage `json:"data,omitempty"`
}

// MessageInput is the input of the host's message.send service.
type MessageInput struct {
	Text   string `json:"text"`
	Thread string `json:"thread,omitempty"`
}

// MessageOutput is the output of message.send.
type MessageOutput struct {
	ID string `json:"id"`
	At string `json:"at"`
}

// ServiceMessageSend is the host service gadgets send messages with.
const ServiceMessageSend = "message.send"

// Message limits.
const (
	MaxMessageText = 4000
	maxThreadLen   = 64
)

var threadPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// Validate checks a message.send input.
func (m MessageInput) Validate() error {
	n := utf8.RuneCountInString(m.Text)
	if n == 0 || n > MaxMessageText || !utf8.ValidString(m.Text) {
		return Errorf(CodeInvalidInput, "text must be 1-%d characters", MaxMessageText)
	}
	if m.Thread != "" && !threadPattern.MatchString(m.Thread) {
		return Errorf(CodeInvalidInput, "thread must be 1-%d of A-Z a-z 0-9 . _ : -", maxThreadLen)
	}
	return nil
}

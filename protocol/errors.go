package protocol

import (
	"context"
	"errors"
	"fmt"
)

// Call error codes (PROTOCOL.md §7).
const (
	CodeUnknownCommand = "unknown_command"
	CodeInvalidInput   = "invalid_input"
	CodeBusy           = "busy"
	CodeCanceled       = "canceled"
	CodeTimeout        = "timeout"
	CodeDenied         = "denied"
	CodeTooLarge       = "too_large"
	CodeUnavailable    = "unavailable"
	CodeFailed         = "failed"
)

// Handshake refusal codes (PROTOCOL.md §3).
const (
	RefuseUnpaired     = "unpaired"
	RefuseTokenInvalid = "token_invalid"
	RefuseTokenExpired = "token_expired"
	RefuseBusy         = "busy"
	RefuseVersion      = "version"
)

// CLOSE codes (PROTOCOL.md §8).
const (
	CloseRevoked       = "revoked"
	CloseReplaced      = "replaced"
	CloseShutdown      = "shutdown"
	CloseProtocolError = "protocol_error"
	CloseTimeout       = "timeout"
)

// RemoteError is a call's failure as carried in a RESULT. Command handlers
// return one to choose the code the caller sees.
type RemoteError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

func (e *RemoteError) Error() string {
	if e.Message == "" {
		return "vgp: " + e.Code
	}
	return fmt.Sprintf("vgp: %s: %s", e.Code, e.Message)
}

// Is makes a peer's timeout and cancellation match context.DeadlineExceeded
// and context.Canceled, so callers handle a deadline the same whichever side
// noticed it first.
func (e *RemoteError) Is(target error) bool {
	switch target {
	case context.DeadlineExceeded:
		return e.Code == CodeTimeout
	case context.Canceled:
		return e.Code == CodeCanceled
	}
	return false
}

// Errorf builds a RemoteError with a formatted message.
func Errorf(code, format string, args ...any) *RemoteError {
	return &RemoteError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// IsCode reports whether err is a RemoteError with the given code.
func IsCode(err error, code string) bool {
	var re *RemoteError
	return errors.As(err, &re) && re.Code == code
}

// HandshakeError is the host's refusal in message 2.
type HandshakeError struct {
	Code    string
	Message string
}

func (e *HandshakeError) Error() string {
	if e.Message == "" {
		return "vgp: handshake refused: " + e.Code
	}
	return fmt.Sprintf("vgp: handshake refused: %s: %s", e.Code, e.Message)
}

// CloseError reports a CLOSE frame received from the peer.
type CloseError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

func (e *CloseError) Error() string {
	if e.Message == "" {
		return "vgp: peer closed: " + e.Code
	}
	return fmt.Sprintf("vgp: peer closed: %s: %s", e.Code, e.Message)
}

// ProtocolError is a violation of the protocol by the peer. Sessions close
// with protocol_error when they detect one.
type ProtocolError struct{ msg string }

func (e *ProtocolError) Error() string { return "vgp: protocol error: " + e.msg }

func protocolErrorf(format string, args ...any) error {
	return &ProtocolError{msg: fmt.Sprintf(format, args...)}
}

// ErrSessionClosed is returned by calls on a session that has ended.
var ErrSessionClosed = errors.New("vgp: session closed")

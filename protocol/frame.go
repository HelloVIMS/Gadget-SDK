package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
)

// FrameType identifies a frame (PROTOCOL.md §5).
type FrameType uint8

// Frame types.
const (
	FrameHello   FrameType = 0x01
	FrameWelcome FrameType = 0x02
	FrameCall    FrameType = 0x10
	FrameResult  FrameType = 0x11
	FrameCancel  FrameType = 0x12
	FrameEvent   FrameType = 0x20
	FramePing    FrameType = 0x30
	FramePong    FrameType = 0x31
	FrameClose   FrameType = 0x7f
)

func (t FrameType) String() string {
	switch t {
	case FrameHello:
		return "HELLO"
	case FrameWelcome:
		return "WELCOME"
	case FrameCall:
		return "CALL"
	case FrameResult:
		return "RESULT"
	case FrameCancel:
		return "CANCEL"
	case FrameEvent:
		return "EVENT"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameClose:
		return "CLOSE"
	}
	return fmt.Sprintf("0x%02x", uint8(t))
}

func (t FrameType) known() bool {
	switch t {
	case FrameHello, FrameWelcome, FrameCall, FrameResult, FrameCancel, FrameEvent, FramePing, FramePong, FrameClose:
		return true
	}
	return false
}

// frameOverhead is type(1) + id(4) + hlen(2).
const frameOverhead = 7

// Frame is one logical VGP message. Header is a JSON object or empty
// (meaning {}); Body is raw bytes.
type Frame struct {
	Type   FrameType
	ID     uint32
	Header []byte
	Body   []byte
}

// NewFrame builds a frame whose header is v marshalled as JSON (empty when
// v is nil).
func NewFrame(t FrameType, id uint32, v any, body []byte) (Frame, error) {
	f := Frame{Type: t, ID: id, Body: body}
	if v != nil {
		h, err := json.Marshal(v)
		if err != nil {
			return Frame{}, fmt.Errorf("vgp: encode %s header: %w", t, err)
		}
		f.Header = h
	}
	return f, nil
}

// DecodeHeader unmarshals the frame's header into v; an empty header
// decodes as {}.
func (f Frame) DecodeHeader(v any) error {
	h := f.Header
	if len(h) == 0 {
		h = []byte("{}")
	}
	if err := json.Unmarshal(h, v); err != nil {
		return protocolErrorf("%s header: %v", f.Type, err)
	}
	return nil
}

// Size is the encoded length of the frame.
func (f Frame) Size() int { return frameOverhead + len(f.Header) + len(f.Body) }

func encodeFrame(f Frame) ([]byte, error) {
	if !f.Type.known() {
		return nil, fmt.Errorf("vgp: unknown frame type %s", f.Type)
	}
	if len(f.Header) > math.MaxUint16 {
		return nil, fmt.Errorf("vgp: %s header of %d bytes exceeds 65535", f.Type, len(f.Header))
	}
	if len(f.Header) > 0 && !isJSONObject(f.Header) {
		return nil, fmt.Errorf("vgp: %s header is not a JSON object", f.Type)
	}
	out := make([]byte, frameOverhead, f.Size())
	out[0] = byte(f.Type)
	binary.BigEndian.PutUint32(out[1:5], f.ID)
	binary.BigEndian.PutUint16(out[5:7], uint16(len(f.Header)))
	out = append(out, f.Header...)
	return append(out, f.Body...), nil
}

func decodeFrame(b []byte) (Frame, error) {
	if len(b) < frameOverhead {
		return Frame{}, protocolErrorf("frame of %d bytes is shorter than its header", len(b))
	}
	f := Frame{Type: FrameType(b[0]), ID: binary.BigEndian.Uint32(b[1:5])}
	if !f.Type.known() {
		return Frame{}, protocolErrorf("unknown frame type %s", f.Type)
	}
	hlen := int(binary.BigEndian.Uint16(b[5:7]))
	if frameOverhead+hlen > len(b) {
		return Frame{}, protocolErrorf("%s header length %d exceeds the frame", f.Type, hlen)
	}
	if hlen > 0 {
		f.Header = b[frameOverhead : frameOverhead+hlen]
		if !isJSONObject(f.Header) {
			return Frame{}, protocolErrorf("%s header is not a JSON object", f.Type)
		}
	}
	if rest := b[frameOverhead+hlen:]; len(rest) > 0 {
		f.Body = rest
	}
	return f, nil
}

func isJSONObject(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) >= 2 && t[0] == '{' && t[len(t)-1] == '}' && json.Valid(t)
}

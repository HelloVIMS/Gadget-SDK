package protocol

import "time"

// MaxTransportMessage is the largest message a Carrier may deliver: the
// Noise limit, which every VGP message must respect.
const MaxTransportMessage = 65535

// Carrier moves whole, ordered, reliable messages between the two ends of a
// session. Implementations must deliver each message intact and in order,
// and must refuse messages larger than MaxTransportMessage.
//
// ReadMessage is called from one goroutine at a time, as is WriteMessage;
// the two may run concurrently.
type Carrier interface {
	ReadMessage() ([]byte, error)
	WriteMessage(p []byte) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
	// RemoteAddr describes the peer for logs, e.g. "192.168.1.30:51234".
	RemoteAddr() string
}

// Package wscarrier carries VGP over WebSocket (PROTOCOL.md §2): one binary
// WebSocket message per VGP message, at ws://<addr>/vgp/1 with subprotocol
// vgp.1.
package wscarrier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hellovims/gadget-sdk/protocol"
)

const (
	// Path is where hosts accept gadget sessions.
	Path = "/vgp/1"
	// Subprotocol is the negotiated WebSocket subprotocol.
	Subprotocol = "vgp.1"
	// DefaultPort is the VIMS host's gadget port.
	DefaultPort = 8189
	// DialTimeout bounds TCP connect plus the WebSocket upgrade.
	DialTimeout = 10 * time.Second
)

// ErrBrowserRefused is returned by Upgrade for requests with an Origin.
var ErrBrowserRefused = errors.New("vgp: browser connections are refused")

type carrier struct {
	ws     *websocket.Conn
	remote string
}

func wrap(ws *websocket.Conn) protocol.Carrier {
	ws.SetReadLimit(protocol.MaxTransportMessage)
	return &carrier{ws: ws, remote: ws.RemoteAddr().String()}
}

func (c *carrier) ReadMessage() ([]byte, error) {
	kind, p, err := c.ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	if kind != websocket.BinaryMessage {
		_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseUnsupportedData, "binary only"), time.Now().Add(time.Second))
		return nil, errors.New("vgp: received a non-binary WebSocket message")
	}
	return p, nil
}

func (c *carrier) WriteMessage(p []byte) error {
	if len(p) > protocol.MaxTransportMessage {
		return fmt.Errorf("vgp: message of %d bytes exceeds %d", len(p), protocol.MaxTransportMessage)
	}
	return c.ws.WriteMessage(websocket.BinaryMessage, p)
}

func (c *carrier) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *carrier) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
func (c *carrier) Close() error                       { return c.ws.Close() }
func (c *carrier) RemoteAddr() string                 { return c.remote }

// Dial opens a carrier to a host at addr (host:port).
func Dial(ctx context.Context, addr string) (protocol.Carrier, error) {
	if err := protocol.ValidateAddr(addr); err != nil {
		return nil, err
	}
	d := websocket.Dialer{
		HandshakeTimeout: DialTimeout,
		Subprotocols:     []string{Subprotocol},
		ReadBufferSize:   16 << 10,
		WriteBufferSize:  16 << 10,
	}
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	u := url.URL{Scheme: "ws", Host: addr, Path: Path}
	ws, resp, err := d.DialContext(ctx, u.String(), nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("vgp: dial %s: %s", addr, resp.Status)
		}
		return nil, fmt.Errorf("vgp: dial %s: %w", addr, err)
	}
	if ws.Subprotocol() != Subprotocol {
		_ = ws.Close()
		return nil, fmt.Errorf("vgp: %s did not negotiate %s", addr, Subprotocol)
	}
	return wrap(ws), nil
}

var upgrader = websocket.Upgrader{
	HandshakeTimeout: DialTimeout,
	Subprotocols:     []string{Subprotocol},
	ReadBufferSize:   16 << 10,
	WriteBufferSize:  16 << 10,
	// Origin is refused before Upgrade is reached; nothing else to check.
	CheckOrigin: func(*http.Request) bool { return true },
}

// Upgrade accepts a gadget's carrier on a host. It answers 403 to browsers
// (any Origin header) and 400 to clients that did not offer vgp.1; on error
// the response has been written.
func Upgrade(w http.ResponseWriter, r *http.Request) (protocol.Carrier, error) {
	if r.Header.Get("Origin") != "" {
		http.Error(w, "gadgets only", http.StatusForbidden)
		return nil, ErrBrowserRefused
	}
	if !offers(r, Subprotocol) {
		http.Error(w, "subprotocol "+Subprotocol+" required", http.StatusBadRequest)
		return nil, fmt.Errorf("vgp: client did not offer %s", Subprotocol)
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return wrap(ws), nil
}

func offers(r *http.Request, proto string) bool {
	for _, p := range websocket.Subprotocols(r) {
		if p == proto {
			return true
		}
	}
	return false
}

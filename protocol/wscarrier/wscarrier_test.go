package wscarrier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hellovims/gadget-sdk/protocol"
)

type echo struct{}

func (echo) HandleCall(ctx context.Context, c *protocol.Call) (*protocol.Reply, error) {
	return &protocol.Reply{Output: c.Input, Body: c.Body}, nil
}
func (echo) HandleEvent(*protocol.Event) {}

func TestSessionOverWebSocket(t *testing.T) {
	host, gadget := mustKey(t), mustKey(t)
	served := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			http.NotFound(w, r)
			return
		}
		c, err := Upgrade(w, r)
		if err != nil {
			served <- err
			return
		}
		conn, _, err := protocol.ServerHandshake(c, host, 5*time.Second, func(remote protocol.Key, _ protocol.ClientHello) protocol.ServerHello {
			return protocol.Accept(protocol.DeviceID(remote), "ws-host")
		})
		if err != nil {
			served <- err
			return
		}
		if _, err := conn.ReadHello(5 * time.Second); err != nil {
			served <- err
			return
		}
		if err := conn.SendWelcome(protocol.Welcome{ID: protocol.DeviceID(conn.RemoteKey()), Time: time.Now().Unix(), Limits: protocol.DefaultLimits}); err != nil {
			served <- err
			return
		}
		s := protocol.NewSession(conn, protocol.SessionConfig{Handler: echo{}})
		served <- s.Run()
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	c, err := Dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, sh, err := protocol.ClientHandshake(c, gadget, host.Public, protocol.ClientHello{Mode: protocol.ModeResume}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Host != "ws-host" {
		t.Fatalf("server hello %+v", sh)
	}
	if _, err := conn.ExchangeHello(protocol.Hello{Name: "ws gadget", Limits: protocol.DefaultLimits}, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	s := protocol.NewSession(conn, protocol.SessionConfig{Handler: echo{}, Initiator: true})
	go s.Run()
	body := make([]byte, 300_000)
	for i := range body {
		body[i] = byte(i * 7)
	}
	r, err := s.Call(context.Background(), "echo", json.RawMessage(`{"ok":1}`), body)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Output) != `{"ok":1}` || len(r.Body) != len(body) || r.Body[299_999] != body[299_999] {
		t.Fatalf("echo over websocket returned %s with %d bytes", r.Output, len(r.Body))
	}
	s.Close(protocol.CloseShutdown, "done")
	select {
	case err := <-served:
		var ce *protocol.CloseError
		if !errors.As(err, &ce) || ce.Code != protocol.CloseShutdown {
			t.Fatalf("host session ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("host session did not end")
	}
}

func TestUpgradeRefusesBrowsersAndWrongSubprotocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := Upgrade(w, r); err == nil {
			c.Close()
		}
	}))
	defer srv.Close()
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + Path

	h := http.Header{"Origin": {"https://evil.example"}}
	if _, resp, err := (&websocket.Dialer{Subprotocols: []string{Subprotocol}}).Dial(u, h); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("browser upgrade: %v %v", err, resp)
	}
	if _, resp, err := websocket.DefaultDialer.Dial(u, nil); err == nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("upgrade without subprotocol: %v %v", err, resp)
	}
}

func TestReadRefusesTextMessages(t *testing.T) {
	got := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r)
		if err != nil {
			got <- err
			return
		}
		_, err = c.ReadMessage()
		got <- err
	}))
	defer srv.Close()
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + Path
	ws, _, err := (&websocket.Dialer{Subprotocols: []string{Subprotocol}}).Dial(u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if err := ws.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := <-got; err == nil || !strings.Contains(err.Error(), "non-binary") {
		t.Fatalf("text message read as %v", err)
	}
}

func TestDialValidatesAddress(t *testing.T) {
	if _, err := Dial(context.Background(), "no-port"); err == nil {
		t.Fatal("dialled an address without a port")
	}
}

func mustKey(t *testing.T) protocol.KeyPair {
	t.Helper()
	kp, err := protocol.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

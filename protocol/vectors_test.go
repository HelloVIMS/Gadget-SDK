package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hellovims/gadget-sdk/protocol/memcarrier"
)

// The vectors pin VGP/1 byte for byte, so other implementations (the ESP32
// firmware's C core) can be checked against this one without a network:
// fixed keys and ephemerals make the handshake and every transport message
// deterministic.

var updateVectors = flag.Bool("update", false, "rewrite testdata/vectors.json")

type keyVector struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

type frameVector struct {
	Type   uint8  `json:"type"`
	ID     uint32 `json:"id"`
	Header string `json:"header"`
	Body   string `json:"body_hex"`
}

type transportVector struct {
	Direction string      `json:"direction"`
	Note      string      `json:"note"`
	Frame     frameVector `json:"frame"`
	Encoded   string      `json:"encoded_frame_hex"`
	Messages  []string    `json:"transport_messages_hex"`
}

type pairingVector struct {
	URI      string   `json:"uri"`
	HostKey  string   `json:"host_key"`
	Addrs    []string `json:"addrs"`
	Token    string   `json:"token"`
	Expires  int64    `json:"expires"`
	HostName string   `json:"host_name"`
}

type vectorFile struct {
	Comment         string            `json:"comment"`
	Protocol        string            `json:"protocol"`
	Prologue        string            `json:"prologue"`
	HostStatic      keyVector         `json:"host_static"`
	GadgetStatic    keyVector         `json:"gadget_static"`
	HostEphemeral   keyVector         `json:"host_ephemeral"`
	GadgetEphemeral keyVector         `json:"gadget_ephemeral"`
	DeviceID        string            `json:"device_id"`
	Message1Payload string            `json:"message1_payload"`
	Message1        string            `json:"message1_hex"`
	Message2Payload string            `json:"message2_payload"`
	Message2        string            `json:"message2_hex"`
	HandshakeHash   string            `json:"handshake_hash_hex"`
	SAS             string            `json:"sas"`
	Transport       []transportVector `json:"transport"`
	Pairing         pairingVector     `json:"pairing"`
}

func seqKey(t *testing.T, start byte) KeyPair {
	t.Helper()
	var p [KeySize]byte
	for i := range p {
		p[i] = start + byte(i)
	}
	kp, err := KeyPairFromPrivate(p[:])
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func kv(kp KeyPair) keyVector {
	return keyVector{Private: hex.EncodeToString(kp.Private[:]), Public: hex.EncodeToString(kp.Public[:])}
}

// recorder captures every message a carrier writes, in order.
type recorder struct {
	Carrier
	mu   *sync.Mutex
	log  *[]recorded
	from string
}

type recorded struct {
	from string
	msg  []byte
}

func (r *recorder) WriteMessage(p []byte) error {
	r.mu.Lock()
	*r.log = append(*r.log, recorded{r.from, append([]byte(nil), p...)})
	r.mu.Unlock()
	return r.Carrier.WriteMessage(p)
}

func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	host, gadget := seqKey(t, 0x10), seqKey(t, 0x40)
	hostEph, gadgetEph := seqKey(t, 0x70), seqKey(t, 0xa0)
	var tok Token
	for i := range tok {
		tok[i] = 0xd0 + byte(i)
	}
	a, b := memcarrier.Pipe()
	var mu sync.Mutex
	var log []recorded
	gc := &recorder{Carrier: a, mu: &mu, log: &log, from: "gadget->host"}
	hc := &recorder{Carrier: b, mu: &mu, log: &log, from: "host->gadget"}

	const welcomeTime = 1767225600
	gadgetLimits := Limits{MaxChunk: MinChunk, MaxMessage: MinMessage, MaxCalls: 2}
	hello := Hello{
		Name:     "Vector Gadget",
		Model:    "ESP32-C5 DevKitC-1",
		Platform: "esp32c5",
		Firmware: "vims-gadget-esp32 1.0.0",
		Commands: []CommandInfo{{Name: "light.set", Description: "Sets the status light", Risk: RiskWrite, Input: json.RawMessage(`{"type":"object","properties":{"rgb":{"type":"string"}},"required":["rgb"]}`)}},
		Limits:   gadgetLimits,
	}
	body := make([]byte, 3000)
	for i := range body {
		body[i] = byte(i % 251)
	}
	call, _ := NewFrame(FrameCall, 2, CallHeader{Command: "light.set", Input: json.RawMessage(`{"rgb":"00ff00"}`), TimeoutMS: 5000}, body)
	result, _ := NewFrame(FrameResult, 2, ResultHeader{OK: true, Output: json.RawMessage(`{"rgb":"00ff00"}`)}, nil)
	ping := Frame{Type: FramePing, ID: 1}

	hostDone := make(chan error, 1)
	var hostConn *Conn
	go func() {
		c, _, err := serverHandshake(hc, host, 5*time.Second, func(remote Key, ch ClientHello) ServerHello {
			return Accept(DeviceID(remote), "vimsbox")
		}, bytes.NewReader(hostEph.Private[:]))
		if err != nil {
			hostDone <- err
			return
		}
		hostConn = c
		if _, err := c.ReadHello(5 * time.Second); err != nil {
			hostDone <- err
			return
		}
		hostDone <- c.SendWelcome(Welcome{ID: DeviceID(c.RemoteKey()), Host: "vimsbox", Time: welcomeTime, Addrs: []string{"192.168.1.20:8189"}, Services: []string{ServiceMessageSend}, Limits: DefaultLimits})
	}()
	conn, sh, err := clientHandshake(gc, gadget, host.Public, ClientHello{Mode: ModePair, Token: tok.String()}, 5*time.Second, bytes.NewReader(gadgetEph.Private[:]))
	if err != nil || !sh.OK {
		t.Fatalf("handshake: %v %+v", err, sh)
	}
	if _, err := conn.ExchangeHello(hello, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := <-hostDone; err != nil {
		t.Fatal(err)
	}
	if err := hostConn.WriteFrame(call); err != nil {
		t.Fatal(err)
	}
	if f, err := conn.ReadFrame(); err != nil || f.Size() != call.Size() {
		t.Fatalf("CALL read back as %v, %v", f.Type, err)
	}
	for _, f := range []Frame{result, ping} {
		if err := conn.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
		if _, err := hostConn.ReadFrame(); err != nil {
			t.Fatal(err)
		}
	}

	m1, _ := json.Marshal(ClientHello{Mode: ModePair, Token: tok.String()})
	m2, _ := json.Marshal(Accept(DeviceID(gadget.Public), "vimsbox"))
	v := vectorFile{
		Comment:         "VGP/1 test vectors. Keys and ephemerals are fixed, so every byte is reproducible. Hex unless noted; *_payload and header are UTF-8 JSON. See PROTOCOL.md.",
		Protocol:        "Noise_IK_25519_ChaChaPoly_SHA256",
		Prologue:        string(Prologue),
		HostStatic:      kv(host),
		GadgetStatic:    kv(gadget),
		HostEphemeral:   kv(hostEph),
		GadgetEphemeral: kv(gadgetEph),
		DeviceID:        DeviceID(gadget.Public),
		Message1Payload: string(m1),
		Message1:        hex.EncodeToString(log[0].msg),
		Message2Payload: string(m2),
		Message2:        hex.EncodeToString(log[1].msg),
		HandshakeHash:   hex.EncodeToString(conn.HandshakeHash()),
		SAS:             conn.SAS(),
	}
	helloFrame, _ := NewFrame(FrameHello, 0, mustValid(t, hello), nil)
	welcome, _ := NewFrame(FrameWelcome, 0, Welcome{ID: DeviceID(gadget.Public), Host: "vimsbox", Time: welcomeTime, Addrs: []string{"192.168.1.20:8189"}, Services: []string{ServiceMessageSend}, Limits: DefaultLimits}, nil)
	// chunk is the max_chunk in force for each frame's sender: HELLO goes out
	// before WELCOME (65535); the host then honours the gadget's 1024; the
	// gadget honours the host's 65535.
	frames := []struct {
		f     Frame
		from  string
		chunk int
		note  string
	}{
		{helloFrame, "gadget->host", MaxTransportMessage, "HELLO in one chunk: before WELCOME the host accepts 65535-byte transport messages"},
		{welcome, "host->gadget", MinChunk, "WELCOME within the gadget's max_chunk of 1024"},
		{call, "host->gadget", MinChunk, "CALL id 2 with a 3000-byte body in transport messages of at most 1024 bytes; every chunk but the last has flags 0x01 (MORE)"},
		{result, "gadget->host", MaxTransportMessage, "RESULT id 2"},
		{ping, "gadget->host", MaxTransportMessage, "PING id 1 with an empty header and body"},
	}
	next := 2 // log[0], log[1] are the handshake messages
	for _, fr := range frames {
		enc, _ := encodeFrame(fr.f)
		per := fr.chunk - chunkOverhead
		n := (len(enc) + per - 1) / per
		if next+n > len(log) {
			t.Fatalf("%s: expected %d transport messages, log has %d left", fr.f.Type, n, len(log)-next)
		}
		tv := transportVector{
			Direction: fr.from,
			Note:      fr.note,
			Frame:     frameVector{Type: uint8(fr.f.Type), ID: fr.f.ID, Header: string(fr.f.Header), Body: hex.EncodeToString(fr.f.Body)},
			Encoded:   hex.EncodeToString(enc),
		}
		for _, m := range log[next : next+n] {
			if m.from != fr.from {
				t.Fatalf("%s: transport message from %s, want %s", fr.f.Type, m.from, fr.from)
			}
			tv.Messages = append(tv.Messages, hex.EncodeToString(m.msg))
		}
		next += n
		v.Transport = append(v.Transport, tv)
	}
	if next != len(log) {
		t.Fatalf("recorded %d transport messages, vectors cover %d", len(log), next)
	}

	p := Pairing{HostKey: host.Public, Addrs: []string{"192.168.1.20:8189", "vimsbox.local:8189"}, Token: tok, Expires: time.Unix(welcomeTime+600, 0), HostName: "vimsbox"}
	uri, err := p.URI()
	if err != nil {
		t.Fatal(err)
	}
	v.Pairing = pairingVector{URI: uri, HostKey: host.Public.String(), Addrs: p.Addrs, Token: tok.String(), Expires: p.Expires.Unix(), HostName: p.HostName}
	return v
}

func mustValid(t *testing.T, h Hello) Hello {
	t.Helper()
	h.Commands = append([]CommandInfo(nil), h.Commands...)
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "vectors.json")
	if *updateVectors {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./protocol -run TestVectors -update)", err)
	}
	if string(want) != string(got) {
		t.Fatal("VGP/1 output no longer matches testdata/vectors.json: the wire format changed")
	}
	var v vectorFile
	if err := json.Unmarshal(want, &v); err != nil {
		t.Fatal(err)
	}
	p, err := ParsePairingURI(v.Pairing.URI)
	if err != nil || p.HostKey.String() != v.Pairing.HostKey || p.Token.String() != v.Pairing.Token {
		t.Fatalf("vector pairing URI does not parse back: %v", err)
	}
}

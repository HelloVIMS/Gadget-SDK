package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustKeyPair(t *testing.T) KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestKeyPairRoundTrip(t *testing.T) {
	kp := mustKeyPair(t)
	again, err := KeyPairFromPrivate(kp.Private[:])
	if err != nil || again.Public != kp.Public {
		t.Fatalf("KeyPairFromPrivate: %v %x != %x", err, again.Public, kp.Public)
	}
	parsed, err := ParseKey(kp.Public.String())
	if err != nil || parsed != kp.Public {
		t.Fatalf("ParseKey(String()) = %x, %v", parsed, err)
	}
	for _, bad := range []string{"", "AAAA", strings.Repeat("A", 43), "!" + kp.Public.String()[1:]} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) accepted", bad)
		}
	}
	if _, err := KeyPairFromPrivate(make([]byte, 31)); err == nil {
		t.Error("31-byte private key accepted")
	}
}

func TestDeviceIDIsStableAndWellFormed(t *testing.T) {
	var k Key
	for i := range k {
		k[i] = byte(i)
	}
	id := DeviceID(k)
	if !ValidDeviceID(id) {
		t.Fatalf("DeviceID = %q, not a valid id", id)
	}
	if id != DeviceID(k) {
		t.Fatal("DeviceID is not deterministic")
	}
	k[0] ^= 1
	if DeviceID(k) == id {
		t.Fatal("different keys gave the same id")
	}
	for _, bad := range []string{"", "g", "G" + id[1:], id + "a", "g0000000000000000", "x" + id[1:]} {
		if ValidDeviceID(bad) {
			t.Errorf("ValidDeviceID(%q) = true", bad)
		}
	}
}

func TestSASFormat(t *testing.T) {
	s := SAS([]byte("handshake hash"))
	if len(s) != 7 || s[3] != ' ' {
		t.Fatalf("SAS = %q", s)
	}
	if SAS([]byte("handshake hash")) != s || SAS([]byte("other")) == s {
		t.Fatal("SAS is not a function of the hash")
	}
}

func testPairing(t *testing.T) Pairing {
	t.Helper()
	tok, err := NewToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Pairing{
		HostKey:  mustKeyPair(t).Public,
		Addrs:    []string{"192.168.1.20:8189", "vimsbox.local:8189", "[fd00::1]:8189"},
		Token:    tok,
		Expires:  time.Unix(1767225600, 0),
		HostName: "vimsbox",
	}
}

func TestPairingURIRoundTrip(t *testing.T) {
	p := testPairing(t)
	uri, err := p.URI()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, PairingScheme) {
		t.Fatalf("URI %q lacks the scheme", uri)
	}
	got, err := ParsePairingURI("  " + uri + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.HostKey != p.HostKey || got.Token != p.Token || !got.Expires.Equal(p.Expires) || got.HostName != p.HostName || strings.Join(got.Addrs, ",") != strings.Join(p.Addrs, ",") {
		t.Fatalf("round trip changed the pairing: %+v vs %+v", got, p)
	}
	if !got.Expired(p.Expires) || got.Expired(p.Expires.Add(-time.Second)) {
		t.Fatal("Expired boundary is wrong")
	}
}

func TestPairingURIRejectsMalformed(t *testing.T) {
	p := testPairing(t)
	good, _ := p.URI()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return PairingScheme + b64(b)
	}
	base := map[string]any{"v": 1, "k": p.HostKey.String(), "a": p.Addrs, "t": p.Token.String(), "e": 1767225600}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range base {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	cases := map[string]string{
		"no scheme":      strings.TrimPrefix(good, PairingScheme),
		"bad base64":     PairingScheme + "%%%",
		"not json":       PairingScheme + b64([]byte("nope")),
		"version 2":      enc(with("v", 2)),
		"short key":      enc(with("k", "AAAA")),
		"no addrs":       enc(with("a", []string{})),
		"addr no port":   enc(with("a", []string{"192.168.1.20"})),
		"addr bad port":  enc(with("a", []string{"h:99999"})),
		"addr with path": enc(with("a", []string{"h/x:80"})),
		"no expiry":      enc(with("e", nil)),
		"short token":    enc(with("t", "AAAA")),
		"control name":   enc(with("n", "bad\x01name")),
		"too many addrs": enc(with("a", []string{"a:1", "a:2", "a:3", "a:4", "a:5", "a:6", "a:7", "a:8", "a:9"})),
		"too long":       PairingScheme + strings.Repeat("A", MaxPairingURI),
	}
	for name, uri := range cases {
		if _, err := ParsePairingURI(uri); err == nil {
			t.Errorf("%s: accepted %q", name, uri)
		}
	}
}

func TestFrameCodec(t *testing.T) {
	f, err := NewFrame(FrameCall, 7, CallHeader{Command: "file.read", Input: json.RawMessage(`{"path":"/etc/hostname"}`)}, []byte{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	b, err := encodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != FrameCall || got.ID != 7 || !bytes.Equal(got.Body, []byte{0, 1, 2}) {
		t.Fatalf("decoded %+v", got)
	}
	var h CallHeader
	if err := got.DecodeHeader(&h); err != nil || h.Command != "file.read" {
		t.Fatalf("header %+v %v", h, err)
	}

	empty, _ := encodeFrame(Frame{Type: FramePing, ID: 3})
	if len(empty) != frameOverhead {
		t.Fatalf("empty PING is %d bytes", len(empty))
	}
	if pf, err := decodeFrame(empty); err != nil || pf.Header != nil || pf.Body != nil {
		t.Fatalf("empty PING decoded %+v %v", pf, err)
	}

	bad := [][]byte{
		{0x10, 0, 0, 0, 1, 0},                   // short
		{0x55, 0, 0, 0, 1, 0, 0},                // unknown type
		{0x10, 0, 0, 0, 1, 0, 9, '{', '}'},      // header longer than frame
		{0x10, 0, 0, 0, 1, 0, 2, '[', ']'},      // header not an object
		{0x10, 0, 0, 0, 1, 0, 3, '{', 'x', '}'}, // header not JSON
	}
	for i, b := range bad {
		if _, err := decodeFrame(b); err == nil {
			t.Errorf("bad frame %d decoded", i)
		}
	}
	if _, err := encodeFrame(Frame{Type: FrameCall, Header: []byte(`[1]`)}); err == nil {
		t.Error("encoded a non-object header")
	}
	if _, err := encodeFrame(Frame{Type: 0x42}); err == nil {
		t.Error("encoded an unknown type")
	}
}

func TestHelloValidation(t *testing.T) {
	ok := Hello{Name: "Kitchen Pi", Commands: []CommandInfo{{Name: "device.health", Risk: RiskRead}, {Name: "x.y_z", Risk: "launch-missiles"}}, Limits: DefaultLimits}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Commands[1].Risk != RiskExec {
		t.Fatalf("unknown risk normalised to %q, want exec", ok.Commands[1].Risk)
	}
	bad := []Hello{
		{Name: "", Limits: DefaultLimits},
		{Name: strings.Repeat("n", 65), Limits: DefaultLimits},
		{Name: "tab\tname", Limits: DefaultLimits},
		{Name: "a", Commands: []CommandInfo{{Name: "Bad"}}, Limits: DefaultLimits},
		{Name: "a", Commands: []CommandInfo{{Name: "a.b"}, {Name: "a.b"}}, Limits: DefaultLimits},
		{Name: "a", Commands: []CommandInfo{{Name: "a", Input: json.RawMessage(`[]`)}}, Limits: DefaultLimits},
		{Name: "a", Caps: json.RawMessage(`"x"`), Limits: DefaultLimits},
		{Name: "a", Limits: Limits{MaxChunk: 100, MaxMessage: MinMessage, MaxCalls: 1}},
		{Name: "a", Limits: Limits{MaxChunk: MinChunk, MaxMessage: 10, MaxCalls: 1}},
		{Name: "a", Limits: Limits{MaxChunk: MinChunk, MaxMessage: MinMessage, MaxCalls: 0}},
	}
	for i, h := range bad {
		if err := h.Validate(); err == nil {
			t.Errorf("bad hello %d validated", i)
		}
	}
}

func TestMessageInputValidation(t *testing.T) {
	if err := (MessageInput{Text: "hi", Thread: "6f1c2d4e-0b7a"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []MessageInput{{}, {Text: strings.Repeat("x", MaxMessageText+1)}, {Text: "hi", Thread: "has space"}, {Text: "hi", Thread: strings.Repeat("t", 65)}} {
		if err := m.Validate(); !IsCode(err, CodeInvalidInput) {
			t.Errorf("%+v: %v", m, err)
		}
	}
}

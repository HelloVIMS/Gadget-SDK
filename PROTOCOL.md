# VIMS Gadget Protocol, version 1 (VGP/1)

VGP connects a **gadget** (a device: an ESP32 board, a Raspberry Pi, any
Linux box) to its owner's **host** (the VIMS daemon on the owner's computer).
The host invokes commands the gadget offers; the gadget calls services the
host offers and sends it events. Everything after the first two messages is
end-to-end encrypted and mutually authenticated; there is no server in the
middle and no account.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Identities

Each side has a long-term Curve25519 key pair (the *static key*).

- The **host key** is generated once per VIMS installation.
- The **gadget key** is generated on the gadget the first time it starts and
  MUST NOT leave it. Re-pairing keeps the key, so a gadget keeps its id.

**Gadget id**: `"g" || lowercase(base32(SHA-256("vgp/1 device-id" || 0x00 || gadget_public_key)[0:10]))`,
RFC 4648 alphabet, no padding — `g` followed by 16 characters of `[a-z2-7]`.
The id is derived from the key, so it cannot be claimed by another gadget.

Keys are written in text as unpadded base64url (RFC 4648 §5) of the 32 raw
bytes.

## 2. Carrier

VGP/1 runs over WebSocket (RFC 6455).

| | |
|---|---|
| URL | `ws://<host>:<port>/vgp/1` |
| Subprotocol | `vgp.1` (`Sec-WebSocket-Protocol`); a side that did not negotiate it MUST close |
| Default port | `8189` |
| Messages | binary only; one WebSocket message carries exactly one VGP message; a text message is a protocol error |
| Size | a WebSocket message MUST NOT exceed 65535 bytes |

The host refuses upgrade requests that carry an `Origin` header: gadgets are
native clients, and refusing browsers keeps web pages on the same network
from occupying handshake slots. The host serves nothing else on this port.

The carrier needs no TLS: VGP encrypts and authenticates on its own. Other
carriers (a relay for gadgets away from home) carry the same messages.

## 3. Handshake

`Noise_IK_25519_ChaChaPoly_SHA256` ([Noise rev. 34](https://noiseprotocol.org/noise.html)),
prologue = the 13 ASCII bytes `vims-gadget/1`.

The gadget is the initiator and MUST know the host key before it connects:
from a pairing URI (§4) the first time, from its stored pairing afterwards.

```
<- s                       (host key, known in advance)
-> e, es, s, ss   + payload  message 1, gadget → host
<- e, ee, se      + payload  message 2, host → gadget
```

The first WebSocket message from the gadget is message 1, the first from the
host is message 2. Each payload is a UTF-8 JSON object of at most 1024 bytes.

**Message 1 payload**

```json
{"m": "pair", "t": "<pairing token, base64url>"}
{"m": "resume"}
```

`pair` presents a one-time token from a pairing URI. `resume` reconnects a
gadget the host already knows by its static key.

**Message 2 payload**

```json
{"ok": true, "id": "gq3mz7xk2abcdefgh", "host": "vimsbox"}
{"ok": false, "e": "unpaired", "msg": "this device is not paired with vimsbox"}
```

| `e` | Meaning | Gadget should |
|---|---|---|
| `unpaired` | the host does not know this gadget key (never paired, or removed) | forget the pairing and wait to be paired again |
| `token_invalid` | the pairing token is unknown or already used | report it; do not retry with the same token |
| `token_expired` | the pairing token has expired | report it; ask for a new pairing URI |
| `busy` | the host refuses new sessions right now | retry with backoff |
| `version` | the host cannot serve this gadget | report it |

After a refusal the host closes the carrier. After `ok`, both sides split the
handshake into two cipher states (gadget→host and host→gadget) and the
session continues with transport messages (§5).

**Short authentication string (SAS)**: both sides MAY display
`SAS = uint32_be(SHA-256("vgp/1 sas" || 0x00 || h)[0:4]) mod 1000000`,
formatted as two groups of three digits (`"042 917"`), where `h` is the
handshake hash after message 2. Equal codes on the host and the gadget prove
both ends completed the same handshake.

## 4. Pairing

The owner opens pairing on the host (VIMS: Settings → Devices → Add device).
The host creates a **ticket**: a 32-byte random token, valid for 10 minutes and
usable once, and shows a pairing URI that the owner gives the gadget (pasted
into its terminal, written over USB, scanned).

```
vimsgadget1:<base64url(JSON)>
```

```json
{
  "v": 1,
  "k": "<host key, base64url>",
  "a": ["192.168.1.20:8189", "vimsbox.local:8189"],
  "t": "<token, base64url of 32 bytes>",
  "e": 1767225600,
  "n": "vimsbox"
}
```

| Field | | |
|---|---|---|
| `v` | required | 1 |
| `k` | required | host static key |
| `a` | required | 1–8 addresses `host:port` to try in order (IPv6 hosts in brackets) |
| `t` | required | pairing token |
| `e` | required | expiry, Unix seconds |
| `n` | optional | the host's display name |

The gadget connects with `{"m":"pair","t":…}`. Because the gadget pins the
host key from the URI, nobody on the network can stand in for the host. The
token proves the gadget was given the URI by the owner. The host stores only
`SHA-256(token)` and compares in constant time.

The host commits the pairing (stores the gadget key) only when it has
received the gadget's `HELLO` (§6): that proves the peer completed the
handshake rather than replaying message 1. If the session fails before
`HELLO`, the ticket becomes usable again until it expires.

Whoever holds the URI can pair one gadget with it, so the URI is a secret
until used. The host shows each new pairing with its SAS; the owner can
compare it with the code the gadget prints and remove a gadget they do not
recognise.

## 5. Transport messages, chunks and frames

Every WebSocket message after the handshake is one Noise transport message:
`ChaChaPoly` with an empty associated data and the implicit counter nonce of
its direction. Decryption failure is fatal: close the carrier.

The plaintext of a transport message is a **chunk**:

```
chunk = flags:u8 || data
```

`flags` bit 0 (`0x01`) is `MORE`: more chunks of the same frame follow. All
other bits MUST be zero. A frame is the concatenation of the `data` of
consecutive chunks up to and including the first one without `MORE`. A
sender MUST NOT interleave chunks of different frames.

```
frame = type:u8 || id:u32_be || hlen:u16_be || header[hlen] || body
```

- `header` is a UTF-8 JSON object, or empty (`hlen = 0`), which means `{}`.
- `body` is the rest of the frame: raw bytes (file contents, images, audio).

| Type | Name | Direction | `id` |
|---|---|---|---|
| `0x01` | `HELLO` | gadget → host, first frame | 0 |
| `0x02` | `WELCOME` | host → gadget, reply to `HELLO` | 0 |
| `0x10` | `CALL` | either | call id, non-zero |
| `0x11` | `RESULT` | either, reply to `CALL` | the call's id |
| `0x12` | `CANCEL` | caller → callee | the call's id |
| `0x20` | `EVENT` | either | 0 |
| `0x30` | `PING` | either | any |
| `0x31` | `PONG` | reply to `PING` | the ping's id |
| `0x7f` | `CLOSE` | either, last frame | 0 |

An unknown frame type, a malformed frame, `HELLO`/`WELCOME` after the first
exchange, or a frame larger than the receiver's `max_message` is a protocol
error: the receiver closes the carrier.

### Limits

Each side announces what it can receive; the other side MUST respect it.

| Field | Meaning | Range |
|---|---|---|
| `max_chunk` | largest transport message (ciphertext, including the 16-byte tag) | 1024 – 65535 |
| `max_message` | largest frame | 16384 – 67108864 |
| `max_calls` | concurrent `CALL`s it will run for the peer | 1 – 64 |

Before `WELCOME` arrives the gadget sends `HELLO` in chunks of at most 65535
bytes and the host accepts a `HELLO` of up to 262144 bytes. The host learns
the gadget's limits from `HELLO` and respects them from `WELCOME` on.

## 6. HELLO and WELCOME

**HELLO** (gadget → host, header):

```json
{
  "name": "Kitchen Pi",
  "model": "Raspberry Pi 5 Model B Rev 1.0",
  "platform": "linux/arm64",
  "firmware": "vims-gadget 0.1.0",
  "commands": [
    {
      "name": "system.run",
      "description": "Runs a shell command and returns its output and exit code",
      "risk": "exec",
      "input": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}
    }
  ],
  "caps": {"display": {"width": 412, "height": 412, "format": "rgb565"}},
  "max_chunk": 65535,
  "max_message": 16777216,
  "max_calls": 8
}
```

| Field | | |
|---|---|---|
| `name` | required | 1–64 characters, no control characters; the owner can rename the gadget on the host |
| `model`, `platform`, `firmware` | optional | up to 128 characters each |
| `commands` | optional | up to 64 command descriptors |
| `caps` | optional | free-form JSON object describing hardware (display, audio, lights, buttons), up to 8 KiB |
| `max_chunk`, `max_message`, `max_calls` | required | §5 |

A **command descriptor** has a `name` (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`,
at most 64 characters, unique), a `description` (at most 512 characters), a
`risk`, and an optional `input` JSON Schema object (at most 8 KiB) describing
the `CALL` input.

| `risk` | Meaning | VIMS host policy |
|---|---|---|
| `read` | only reads state | runs without asking |
| `write` | changes state on the gadget (files, settings, actuators) | asks the owner, per the HITL level |
| `exec` | runs arbitrary code | asks the owner, per the HITL level |

An unknown `risk` is treated as `exec`.

**WELCOME** (host → gadget, header):

```json
{
  "id": "gq3mz7xk2abcdefgh",
  "host": "vimsbox",
  "time": 1767225000,
  "addrs": ["192.168.1.20:8189", "vimsbox.local:8189"],
  "services": ["message.send"],
  "max_chunk": 65535,
  "max_message": 16777216,
  "max_calls": 8
}
```

`addrs` are where the host can be reached now; a gadget SHOULD store them and
try them, most recently successful first, when it reconnects. `time` lets a
gadget without a clock set one.

A host that rejects a `HELLO` (invalid fields) sends `CLOSE` with
`protocol_error`.

## 7. Calls

```
CALL    header {"cmd": "file.read", "input": {...}, "timeout_ms": 60000}   body: optional input bytes
RESULT  header {"ok": true, "output": {...}}                              body: optional output bytes
RESULT  header {"ok": false, "error": {"code": "invalid_input", "message": "path is required"}}
CANCEL  header {}
```

- Gadget-originated calls use odd ids, host-originated calls even ids, so
  ids never collide. Ids are not reused within a session.
- `timeout_ms` (optional) is how long the caller will wait. The callee SHOULD
  abandon the work when it passes.
- `CANCEL` tells the callee the caller stopped waiting; the callee SHOULD
  abort and MAY still send a `RESULT`, which the caller ignores.
- A `RESULT` for an unknown id is ignored.
- A callee running `max_calls` calls answers further calls immediately with
  `busy`.

| Error code | Meaning |
|---|---|
| `unknown_command` | no such command or service |
| `invalid_input` | the input does not match the command |
| `busy` | too many concurrent calls, or rate limited |
| `canceled` | the call was cancelled |
| `timeout` | the work did not finish in time |
| `denied` | the callee refuses (policy, permissions) |
| `too_large` | input or output exceeds a limit |
| `unavailable` | the callee cannot do this right now |
| `failed` | anything else; `message` says what |

### Host services (gadget → host)

| Service | Input | Output |
|---|---|---|
| `message.send` | `{"text": "…", "thread": "optional"}` — text of 1–4000 characters; `thread` (at most 64 of `[A-Za-z0-9._:-]`) groups messages into a side conversation | `{"id": "m-…", "at": "<RFC 3339>"}` |

The VIMS host shows each message to the owner as a notification and keeps the
latest ones per gadget. It accepts at most 30 messages per minute per gadget
(`busy` beyond).

## 8. Events, keepalive, close

`EVENT` header `{"name": "…", "data": {...}}`, optional body. Fire-and-forget,
either direction; a receiver ignores names it does not know.

`PING` / `PONG`: a receiver MUST answer every `PING` with a `PONG` carrying the
same id. A gadget MUST send a `PING` after 25 seconds without sending anything
and SHOULD close the carrier when it has received nothing for 60 seconds. A
host SHOULD close a session that sent nothing for 75 seconds.

`CLOSE` header `{"code": "…", "message": "…"}` is the last frame a side sends
before closing the carrier.

| Code | |
|---|---|
| `revoked` | the owner removed this gadget; a gadget forgets its pairing |
| `replaced` | the same gadget opened a newer session |
| `shutdown` | the sender is stopping |
| `protocol_error` | the sender received something invalid |
| `timeout` | the sender received nothing for too long |

The host keeps one session per gadget; a new session replaces the old one.

## 9. Security notes

- Mutual authentication: the gadget authenticates the host by the pinned host
  key; the host authenticates the gadget by its static key (resume) or the
  pairing token (pair). Noise IK gives forward secrecy once message 2 is
  processed and hides the gadget key from observers.
- Message 1 is replayable in IK; a replay cannot complete a session (the
  replayer lacks the gadget's ephemeral key). The host therefore acts on a
  session only after the first transport frame (`HELLO`) decrypts.
- A gadget's commands run with whatever authority the gadget has. A command
  with `risk: read` MUST NOT change state.
- A pairing URI is a one-time secret. Pairing has no manufacturer
  attestation; the owner's control of the URI and the SAS are the trust
  anchors.

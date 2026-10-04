# VIMS Gadget SDK — notes for coding agents

Open source (Apache 2.0). The VIMS daemon (the host) consumes `protocol/` as
a Go module dependency; nothing here may depend on VIMS code.

## Layout

| Path | |
|---|---|
| `PROTOCOL.md` | VGP/1 specification — the contract. Change it together with the code. |
| `protocol/` | Both ends of the wire: keys, pairing URIs, Noise IK handshake (`ClientHandshake`/`ServerHandshake`), chunked frames (`Conn`), `Session` (calls, results, events, keepalive). Carrier-agnostic. |
| `protocol/wscarrier` | WebSocket carrier (`ws://host:8189/vgp/1`, subprotocol `vgp.1`). |
| `protocol/memcarrier` | In-memory carrier pair for tests and simulators. |
| `protocol/testdata/vectors.json` | Byte-exact vectors (fixed keys and ephemerals) for other implementations. |
| `gadget/` | Device runtime: `Config`, `Command`, `Store`/`FileStore`, `Device.Run`/`Pair`/`SendMessage`. |
| `linux/`, `cmd/vims-gadget` | The Linux agent. See `linux/AGENTS.md`. |

## Rules

- A wire-format change updates `PROTOCOL.md`, regenerates the vectors
  (`make vectors`) and says so in the commit. `TestVectors` fails on any
  unintended byte change.
- Keep `protocol/` free of carrier specifics and of anything host-side
  beyond what both ends need.
- Event handlers must not block: `HandleEvent` runs on the session's read
  loop. Calls run on their own goroutines and must honour `ctx`.
- Limits are part of the protocol (`max_chunk`, `max_message`, `max_calls`):
  small boards lower them in `gadget.Config.Limits`, and a sender must
  respect the peer's.
- Commits: no `Generated with` or `Co-Authored-By` trailers.

## Checks

```bash
make vet && make test
```

Tests need no network or hardware. Cross-compile the agent with `make linux`
(arm64, armv7, armv6, amd64) before releasing.

# VIMS Gadget SDK

Build your own devices for [VIMS](https://vims.com). A gadget is hardware you
own — a Raspberry Pi, a Linux box, a board on your bench — that your VIMS
assistant can use: run its commands, read its sensors, drive what it is
wired to. Your gadgets talk to the VIMS app on your own computer. No cloud
and no account sit in between, and nobody else can reach them.

| | |
|---|---|
| [`linux/`](linux/) | **Linux agent.** Install it on a Raspberry Pi or any Linux machine and VIMS can run commands, move files and check health there. Programs on the machine can message you. |
| [`gadget/`](gadget/) | **Go gadget runtime.** Write your own gadget in Go: describe its commands, call `Run`, and it pairs, reconnects and serves VIMS. |
| [`protocol/`](protocol/) | **The VIMS Gadget Protocol (VGP/1)** in Go: Noise handshake, frames, sessions, pairing URIs. Both ends of the wire. |
| [`PROTOCOL.md`](PROTOCOL.md) | The specification, for implementations in other languages. [`protocol/testdata/vectors.json`](protocol/testdata/vectors.json) pins it byte for byte. |

## How it works

1. In VIMS, open **Settings → Devices → Add device**. VIMS shows a pairing
   URI, valid for 10 minutes and usable once.
2. Give the URI to the gadget (`vims-gadget pair '…'` on Linux).
3. The gadget pins your VIMS's key from the URI, connects, and stays
   connected across reboots and network changes.

From then on your assistant sees the gadget's commands as tools. Commands
that only read (`device.health`, `file.read`) run straight away; commands
that change or run things (`file.write`, `system.run`) ask you first, the
same way every other risky action in VIMS does.

Every session is end-to-end encrypted and mutually authenticated (Noise IK).
Both sides can show a six-digit code after pairing; if the codes match,
nobody stood in between.

## Build a gadget in Go

```go
store, _ := gadget.NewFileStore("/var/lib/my-gadget")
dev, err := gadget.New(gadget.Config{
	Name:  "Desk lamp",
	Model: "Pi Zero 2 W lamp",
	Store: store,
	Commands: []gadget.Command{{
		Name:        "light.set",
		Description: "Turns the lamp on or off",
		Risk:        protocol.RiskWrite,
		Input:       json.RawMessage(`{"type":"object","properties":{"on":{"type":"boolean"}},"required":["on"]}`),
		Handler: func(ctx context.Context, req *gadget.Request) (*gadget.Response, error) {
			var in struct{ On bool `json:"on"` }
			if err := req.Decode(&in); err != nil {
				return nil, err
			}
			setLamp(in.On)
			return &gadget.Response{Output: map[string]bool{"on": in.On}}, nil
		},
	}},
})
if err != nil {
	log.Fatal(err)
}
go dev.Run(ctx)
res, err := dev.Pair(ctx, uriFromVIMS) // once; Run remembers the host
fmt.Println("paired as", res.ID, "code", res.SAS)
```

`dev.SendMessage(ctx, "The lamp's bulb burnt out", "")` messages you;
`dev.Notify` sends events.

## Develop

Go 1.24 or later. The tests need no network and no hardware:

```bash
make test          # go test -race ./...
make vet           # gofmt + go vet
make linux         # static agents for arm64, armv7, armv6 and amd64 in dist/
make vectors       # regenerate protocol/testdata/vectors.json after a deliberate wire change
```

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

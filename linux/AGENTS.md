# Linux agent — notes for coding agents

## Layout

- `commands/` — the command set. `All()` lists every command; each has a
  name, description, `Risk`, input JSON Schema and handler.
- `control/` — the local control socket (`status`, `pair`, `unpair`, `send`)
  the CLI uses.
- `service/` — systemd install/uninstall.
- `../cmd/vims-gadget` — the CLI and service entry point.

Everything here is `//go:build linux`.

## Adding a command

1. Write the handler in `commands/` as
   `func(ctx context.Context, req *gadget.Request) (*gadget.Response, error)`.
   Decode input with `req.Decode(&in)` (unknown fields are refused). Return
   `protocol.Errorf(protocol.CodeInvalidInput, …)` for bad input,
   `CodeDenied` for permission problems; other errors become `failed`.
2. Add it to `All()` with an honest `Risk`: `read` only if it changes
   nothing — VIMS runs read commands without asking the owner. Anything that
   writes, actuates or executes is `write` or `exec`.
3. Give it an input schema the assistant can follow (`description` on every
   property, `required`, `additionalProperties: false`). Descriptor limits:
   name `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$` up to 64 characters,
   description up to 512, schema up to 8 KiB.
4. Honour `ctx`: the host cancels calls and sets deadlines.
5. Test it in `commands/commands_test.go`; `TestCommandSetIsComplete` lists
   the expected names and risks.

## Checks

```bash
gofmt -l . && go vet ./... && go test -race ./...
```

`cmd/vims-gadget/main_test.go` builds the binary and drives it through the
control socket. Cross-compile before shipping: `make linux`.

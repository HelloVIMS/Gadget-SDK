# Linux agent

`vims-gadget` turns any Linux computer — a Raspberry Pi, a NAS, an old
laptop — into a VIMS gadget. Install it, pair it, and your VIMS assistant can
run commands, move files and check health on the machine. Programs on the
machine can send you messages.

> VIMS gets exactly the access of the account you install the agent for. If
> that account can use sudo, so can VIMS — choose an account without sudo if
> that is not what you want.

## What you need

- A Linux machine with systemd (Raspberry Pi OS, Debian, Ubuntu, Fedora, …),
  32- or 64-bit ARM or x86-64.
- Network access from the machine to the computer running VIMS (same Wi-Fi
  or LAN, or a VPN such as Tailscale).
- VIMS on your computer, for the pairing URI.

## Install

Build the agent for your machine on any computer with Go 1.24+ (`make linux`
at the repository root writes `dist/vims-gadget-linux-{arm64,armv7,armv6,amd64}`),
copy it over, then on the machine:

```bash
sudo ./vims-gadget install --pair 'vimsgadget1:…'
```

Get the URI in VIMS: **Settings → Devices → Add device**. The installer tells
you which account VIMS will use and whether it can sudo, asks before going
ahead, installs `/usr/local/bin/vims-gadget`, starts the `vims-gadget`
service and pairs. It prints a six-digit code; VIMS shows the same code next
to the new device.

| Option | |
|---|---|
| `--user NAME` | the account VIMS uses (default: whoever ran `sudo`) |
| `--name NAME` | how the gadget shows up in VIMS (default: the hostname; you can rename it in VIMS) |
| `--pair URI` | pair right after installing |
| `--yes` | do not ask for confirmation |

The service connects to VIMS on its own after reboots and network changes.
The pairing URI expires after 10 minutes and works once; to pair again, make
a new one and run `vims-gadget pair 'vimsgadget1:…'`.

## What VIMS can do

| Command | Risk | What it does |
|---|---|---|
| `system.run` | exec | Runs a shell command, returns exit code, stdout and stderr (256 KiB each); killed after `timeout_ms` (default 60 s, at most 10 min) |
| `file.read` | read | Reads up to 64 KiB of a file at an offset |
| `file.write` | write | Writes a file, replacing it only when complete; large files in chunks of up to 1 MiB |
| `device.health` | read | Hostname, OS, kernel, uptime, load, memory, disk and temperature |

VIMS runs `read` commands without asking and asks you before `write` and
`exec` ones, as set in Settings → Security.

Ask VIMS things like:

> What's using all the disk space on my Pi?

> Install Home Assistant on the Pi and tell me how to open it.

> Every morning at 7, check that the Pi's backups ran and tell me if they didn't.

## Messages from the machine

Programs on the machine can message you, with no credentials of their own:

```bash
vims-gadget send-user-msg "The garage door has been open for an hour."
vims-gadget send-user-msg --session-id garage "Closed again."
```

Messages show up as VIMS notifications and under the device in Settings →
Devices; `--session-id` groups related messages. Any program running as the
agent's account or in its group can use the control socket
(`/run/vims-gadget/control.sock`, mode 0660).

## Manage it

```bash
vims-gadget status                        # id, host, connection state
sudo systemctl status vims-gadget         # is the service running?
sudo journalctl -u vims-gadget -f         # follow the log
vims-gadget pair 'vimsgadget1:…'          # pair with VIMS again
vims-gadget unpair                        # forget the host (remove it in VIMS too)
sudo vims-gadget uninstall [--purge]      # remove the service; --purge also deletes the key and pairing
```

The gadget's key and pairing live in `/var/lib/vims-gadget`, readable only by
the agent's account. The key never leaves the machine and stays the same
across re-pairing, so the device keeps its id.

## Develop

```bash
go test ./linux/... ./cmd/...
go run ./cmd/vims-gadget run --state-dir /tmp/vg --socket /tmp/vg.sock --name dev
VIMS_GADGET_SOCKET=/tmp/vg.sock go run ./cmd/vims-gadget pair 'vimsgadget1:…'
```

To add a command, see [`AGENTS.md`](AGENTS.md).

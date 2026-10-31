# T3 Code gadget example
An opt-in bridge from a paired VIMS host to **one owner-configured T3 Code
project**, using T3's supported local `t3 thread` CLI. It delegates to T3 rather
than implementing another coding agent or reading T3's private token store.
## Run locally
Install a trusted T3 CLI, register the project in T3, and start the T3 server as
the same OS user. Then build this example:
```sh
go build -o t3-gadget ./examples/t3-gadget
./t3-gadget -t3 /absolute/path/to/t3 -project /absolute/path/to/project
```
The default command catalog is read-only. Add `-allow-writes` only after reviewing
the configured project's model and permission defaults. Every new task gets a
**new Git worktree**, based on `HEAD` (override with `-base-ref main`, for example).
The bridge never sets T3's full-access mode, selects a different provider, merges
changes, or deploys anything. T3's project defaults still govern the agent.
On first run, create a gadget pairing URI in VIMS and provide it on stdin rather
than in the process argument list. For example, put the URI in a local private
file, use `-pair-stdin < private-pairing-uri.txt`, and compare the printed
verification code with VIMS. Treat the URI as a secret and remove the temporary
file afterward. Subsequent runs use the persisted pairing; no pairing input is
needed. Stop the example with Ctrl+C. No service is installed automatically.
The executable must be an absolute, trusted path. Unix executable/shebang
launchers work. On Windows use a native executable; `.cmd`/`.bat` launchers are
not run through a shell. Linux process execution is covered by automated tests;
Windows binaries are compile-checked, not exercised against a live T3 install.
## Commands
| Command | Risk | Behavior |
| --- | --- | --- |
| `t3.capabilities` | read | Explicit supported/unsupported capabilities |
| `t3.threads.list` | read | Top-level threads in the configured project |
| `t3.thread.read` | read | Status, pending requests, and 1ΓÇô50 recent messages |
| `t3.request.read` | read | Submission receipt, **not** agent completion |
| `t3.thread.start` | exec, opt-in | Submit a prompt in a new worktree |
| `t3.thread.send` | exec, opt-in | Queue a follow-up; never interrupt |
Start input:
```json
{"request_id":"research-to-code-001","prompt":"Implement the attached research conclusions, run tests, and report the diff. Do not deploy."}
```
The prompt travels on stdin, never in a shell command or process arguments. The
response contains T3's `threadId` and `runId`. Poll `t3.thread.read` with
`{"thread_id":"<returned id>"}` to inspect progress and waiting/approval state.
Answer approval requests in T3's own UI. A handoff can include objectives,
constraints, evidence locations, and acceptance tests in the prompt; this does
not pretend to copy a provider's hidden state or native conversation history.
## Replay protection and uncertain outcomes
Writes require a caller-chosen `request_id`. Before invoking T3, the bridge
creates an exclusive, synced receipt claim. The receipt hashes the operation,
project, base ref and normalized input; it **does not retain the prompt**.
- `pending`: the submission may still be in flight, or the bridge may have
  stopped before learning its outcome.
- `accepted`: T3 acknowledged submission. Identical retries return that stored
  acknowledgement without launching again. This does not mean the agent finished.
- `unknown`: command failure, cancellation, incompatible output, or a lost
  acknowledgement made the submission outcome uncertain. The bridge does not
  retry it automatically.
Reusing an ID with different input/configuration is rejected. Inspect both
`t3.request.read` and T3 before resolving a pending/unknown request. Start titles
include `VIMS <request_id>` to aid reconciliation. Do not delete receipts or use a
new ID merely to bypass uncertainty: that can duplicate real work. Corrupt or
partially written claims fail closed. Receipts survive ordinary process restarts
and are retained until the owner archives/removes them after reconciliation.
This is **replay suppression, not exactly-once execution**. Cancelling a VGP call
kills only its local CLI process; T3 may already have accepted the task and its
agent may continue running. There is no fabricated `t3 thread stop` command.
Power-loss durability depends on the filesystem; directory fsync is used on Unix
but is not exposed portably by Go on Windows. Keep the state directory private and
on a reliable local filesystem, not an untrusted or weakly consistent share.
## Trust and limits
The local T3 CLI acts as the machine owner. Project checks constrain which
threads this bridge exposes, **not what filesystem/network access a T3 coding
agent can exercise**. Git worktrees are change isolation, not security sandboxes.
Only pair with a trusted VIMS host, and enforce exec-risk approvals there.
Each CLI call is capped at 30 seconds, stdout at 256 KiB and stderr at 16 KiB;
there are at most four incoming VGP calls at once. Prompts are capped at 32 KiB.
Large thread lists/messages fail rather than silently truncating JSON; request
fewer messages or inspect T3 directly. Raw stderr is not returned or stored.
No automatic agent approval, stop, native fork, cross-provider migration,
remote-MCP OAuth, or remote machine management is claimed.
## Compatibility and validation
CLI contract reference (no T3 source is bundled):
- [T3 outside-agent documentation](https://github.com/pingdotgg/t3code/blob/54c5f25249961a1aa0b61932329092eadbd9d6fc/docs/user/outside-agents.md)
- [T3 thread CLI](https://github.com/pingdotgg/t3code/blob/54c5f25249961a1aa0b61932329092eadbd9d6fc/apps/server/src/cli/thread.ts)
This example is original adapter code under the SDK's Apache-2.0 license. T3
remains a separately installed program under its own license. CLI flags/JSON
responses are checked against that pinned source revision. Contract tests use
fake T3 responses and real helper processes; they are not evidence of a live
VIMS-desktop-to-T3-provider session.
```sh
go test -race ./...
go vet ./...
go build ./examples/t3-gadget
```
Before production use, maintainers should pair it with their actual VIMS build,
exercise read-only commands, then opt into a harmless disposable-project task
and verify worktree creation, queued messages, approvals and restart recovery.

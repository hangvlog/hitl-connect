# HITL Connect

HITL Connect is a Go desktop client and CLI for explicitly authorized remote access, SSH/SFTP and loopback TCP forwarding through a compatible HTTPS/WSS relay. Windows can run an account-scoped embedded SSH service. The local web panel listens on loopback only.

This repository contains the client, its tests and Windows installer source. It does **not** include a hosted relay, server deployment, credentials or device profiles. A compatible relay must be supplied by the operator; a generic WebSocket server or FRP server is not interchangeable with it.

## Build

```sh
git clone https://github.com/hangvlog/hitl-connect.git
cd hitl-connect
go mod download
go test ./...
go build -trimpath -o ../hitl-connect-cli .
../hitl-connect-cli agent help
```

Go 1.26.3 is used by CI; dependencies are pinned in go.mod/go.sum. Windows binary builds also require Python 3.12+. From a clean committed checkout:

```sh
python build-windows-binaries.py ../windows-output/HITL-Connect-Windows 2026.10.15-agent.3 --installer-helper
```

Outputs are GUI, CLI and installer helper executables with source revision metadata. See [Windows packaging](installer/README.md). CI validation artifacts are **unsigned test builds**, not trusted signed releases.

## Configure locally

Provider: open the GUI, enter your relay base URL, choose the local account and explicitly allow access. Windows requests UAC for service installation. CLI equivalent:

```sh
hitl-connect-cli agent allow --relay https://relay.example.invalid --user '<local-account>' --output '<private-code-file>' --dir '<private-profile-directory>'
```

The example hostname is deliberately non-routable. Supply your own compatible deployment. Subsequent use preserves existing local configuration; relay changes require an independently chosen profile, not replacement of an existing identity.

Caller:

```sh
hitl-connect-cli agent start --role connect --key-file '<private-code-file>' --dir '<private-profile-directory>' --wait
hitl-connect-cli agent status --dir '<private-profile-directory>'
```

Connection codes contain the relay address and access authority; they are private. Do not paste them into issues, source files or workflow inputs. Runtime settings and logs live outside the source tree. No endpoint or logging destination is bundled, and remote diagnostic reporting is disabled unless explicitly configured in the local profile.

## Security and limitations

WSS protects the connection to the relay; device-to-device TLS with pinned certificates protects forwarded payloads from the relay. SSH also encrypts SSH sessions. The relay still observes connection metadata. Encryption does not hide destination IPs or program behavior from endpoint administrators.

GUI/agent login checks using the application-managed `ssh-login.key` and an existing host pin use the built-in SSH client: one handshake validates the pinned key, authenticates and runs `whoami`, without a system SSH process. Imported keys and agent/default-identity selection retain the native OpenSSH path. This changes login-check latency, not file-transfer throughput.

Authorization, identity and host-trust checks remain enabled. Embedded Windows sessions run under the explicitly selected logged-in account, not the service's SYSTEM identity. Administrator mode is an explicit choice. Some advanced system OpenSSH migration tools retain historical service/file aliases; these do not conceal SSH capabilities or grant permission to bypass security controls.

v2 is the default. A compatible deployment may explicitly enable `protocol: "v3"` in the local profile. v3 separates control and data channels; it does not resume interrupted SSH streams or replay commands. Capacity waits are bounded and do not terminate existing sessions. A caller defaults to 32 simultaneous connections and 128 FIFO waiting requests. Each queued request expires after 15 seconds within the 25-second establishment budget. A v3 provider defaults to 64 reservations; idle channels grow from 2 to at most 16 with active demand and shrink after 10 seconds of inactivity. Older relays retain their advertised limit (4 when absent). Saturation beyond that budget still fails explicitly; commands are never replayed. Transfer framing reuses per-stream buffers without changing the wire format, encryption or 32 KiB frame limit.

[Windows usage](README-WINDOWS.md) · [Agent operations](AGENT-SETUP.md) · [Security review](SECURITY-REVIEW.md) · [Privacy](PRIVACY.md)

## Code signing policy

See [Code signing policy](CODE-SIGNING.md). SignPath Foundation eligibility and trusted-build requirements have been researched; no certificate, subscription or signing approval is claimed. Signed release publication must stop on a signing failure or timeout.

## License

Apache-2.0. Copyright 2026 HITL Connect contributors. Dependency licenses and notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and `licenses/`. This initial public source snapshot intentionally imports no private repository history.

## Multiple agents and durable jobs

See [capacity and jobs](docs/multi-agent.md) for limits, deployment order, command syntax and acceptance criteria. Capacity changes require upgrading the relay as well as both endpoints. No claim of thirty concurrent WAN sessions follows from compilation or local tests alone.

## Publish a local HTTP API

An existing provider can publish explicit loopback HTTP services from the local panel's
“发布本地 HTTP 服务” section. Enter a port and an optional stable service name. The
panel returns the public URL and can copy private caller credentials. This does not
restart SSH sessions; the background panel owns a separate reconnecting HTTP connection.
Disabling a service stops new calls and closes its active HTTP requests. Stopping SSH
alone does not disable HTTP publications; disable them separately or quit the provider.

Relay outages (HTTP 429/5xx and network failures) use exponential cooldowns of
5, 10, 20, 40, 80, 160, then 300 seconds, with 0–20% positive jitter. Once at
the cap, a persistent outage receives at most one probe every five minutes per
relay origin per process. SSH slots, HTTP publications and enrollment share the
gate: at most eight initial handshakes may already be in flight, and only one
probe is admitted during recovery. Independent processes/devices have independent
gates; their jitter reduces synchronization but is not a server-wide rate limit.
`Retry-After` seconds and HTTP dates extend cooldowns (bounded to 24 hours).
Brief successful handshakes do not reset the failure history; a healthy minute
does. Cancellation ends waiting promptly, and no application request is replayed.
HTTP reconnect logs include the next delay. Fully disabled publication records
remain synchronized with the relay, using the same outage backoff.

Automatic reconnect stops after **two hours from the first failure**, including
cooldown and enrollment time. No new network attempt is admitted at or after the
deadline. SSH and HTTP have separate clocks; an acknowledged connection must
remain online for 60 seconds to clear its outage. A successful HTTP/WebSocket
handshake alone does not reset the clock. Private `reconnect-ssh.json` and
`reconnect-http.json` files retain the first failure and stopped state across
process/service restarts. Opening the panel, diagnosis and automatic recovery
do not reset them. Click Start (or run `agent start --dir <existing-profile>`)
to explicitly retry; CLI-only HTTP publishers use `http resume --config ...`.
This preserves identities and does not replay interrupted commands or requests.

Provider retry budgets track registration, control and waiting-slot failures.
An individual peer's authentication, command, disconnect or stream error is
reported for that session without stopping the provider. Overlapping acknowledged
idle slots and sessions share the healthy minute across v2 pairing handoffs;
a failure restarts that minute on any still-live channel. Caller stream closure
also does not count as a new connection-establishment failure.

CLI equivalent (existing provider identity required):

```sh
hitl-connect-cli http publish --config /private/provider/config.json --port 8000 --name model-api --output /private/model-api-credentials.json
hitl-connect-cli http run --config /private/provider/config.json
hitl-connect-cli http list --config /private/provider/config.json
hitl-connect-cli http disable --config /private/provider/config.json --name model-api
```

The GUI/background provider starts HTTP publications automatically; `http run` is for
CLI-only providers. Output credentials must be a new file outside the identity directory.
Only the credential file contains the token; ordinary command output and service lists
omit it. The name defaults to the decimal port. Changing a target port under the same
name preserves the URL and token. Profiles and `http-services.private.json` are private.
The signed publication includes the actual local port so a compatible management
catalog can display named services without guessing their targets.

For an account-enabled control plane, request a one-time device claim challenge while
logged in, save it as JSON on the provider, then produce the ownership proof:

```sh
hitl-connect-cli http claim-proof --config /private/provider/config.json --challenge challenge.json --output proof.json
```

Submit that proof to the control plane while logged into the same account. It signs the
device ID, account ID and expiring nonce using the existing provider key; the key stays
on the device. The output must be a new file outside the identity directory.

A compatible relay serves `/services/{deviceId}/{service}/{originalPath}` relative to its
API root (for example `/hitl/services/...` with that deployment prefix). Callers send
`X-Hitl-Service-Token`; business `Authorization` remains separate. The independent token
is scoped to one device/service and never grants SSH access. HTTP/SSE, binary payloads
and cancellation are supported; browser WebSocket, CONNECT, cookies and arbitrary web
hosting are not. The HTTPS gateway terminates HTTP payload encryption; this does not
change the end-to-end TLS of the existing SSH/TCP transport. No request is replayed.

### Device address reporting

Authenticated relay connections report up to 16 active unicast interface IPv4/IPv6 addresses in `X-Connect-Local-Ips`. Loopback, link-local and multicast addresses are excluded. No MAC address, interface name, DNS settings or network scan is collected. Relays may show these self-reported addresses in the account-protected device directory. This metadata is informational and is never an authentication factor. Older relays ignore the optional header.

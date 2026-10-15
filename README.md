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
python build-windows-binaries.py ../windows-output/HITL-Connect-Windows 2026.10.15-agent.1 --installer-helper
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

Authorization, identity and host-trust checks remain enabled. Embedded Windows sessions run under the explicitly selected logged-in account, not the service's SYSTEM identity. Administrator mode is an explicit choice. Some advanced system OpenSSH migration tools retain historical service/file aliases; these do not conceal SSH capabilities or grant permission to bypass security controls.

v2 is the default. A compatible deployment may explicitly enable `protocol: "v3"` in the local profile. v3 separates control and data channels; it does not resume interrupted SSH streams or replay commands. Capacity waits are bounded and do not terminate existing sessions.

[Windows usage](README-WINDOWS.md) · [Agent operations](AGENT-SETUP.md) · [Security review](SECURITY-REVIEW.md) · [Privacy](PRIVACY.md)

## Code signing policy

See [Code signing policy](CODE-SIGNING.md). SignPath Foundation eligibility and trusted-build requirements have been researched; no certificate, subscription or signing approval is claimed. Signed release publication must stop on a signing failure or timeout.

## License

Apache-2.0. Copyright 2026 HITL Connect contributors. Dependency licenses and notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and `licenses/`. This initial public source snapshot intentionally imports no private repository history.

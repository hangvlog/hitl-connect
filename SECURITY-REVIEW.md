# Security review

HITL Connect provides remote command execution and file transfer for accounts explicitly authorized by the device owner. It is a remote access/tunneling application and must be described as such.

- Device private keys remain local. Public certificates and enrollment metadata are sent to the configured relay. Forwarded payloads use device-to-device TLS with trust validation.
- Connection codes contain invitation authority and the relay address. Possession can grant access under the local account authorization. Treat codes as secrets, share privately and revoke when required.
- The embedded Windows provider's control service runs as LocalSystem; account workers and commands use the explicitly authorized account token. Administrator mode is separately selected. The account must be logged in.
- The local panel binds loopback and authenticates API requests. Installing a desktop shortcut alone does not authorize remote access.
- Local audit records authorization and session metadata, not original command/file contents. Missing audit storage fails closed for new embedded sessions. Administrators can modify local audit files.
- Optional system OpenSSH tools use existing system keys and accounts; historical file/service aliases retain the underlying Microsoft binary identity. They are not an evasion mechanism or substitute for endpoint authorization.
- Upgrade failures preserve identities and rollback material. Protection rejections must be surfaced, not bypassed.

Code signing proves publisher/source provenance and integrity. It does not promise SmartScreen reputation, antivirus acceptance, vulnerability absence or authorization to use remote access on an organization's network.

Report a vulnerability privately through the repository's security reporting channel when enabled. Do not include keys, connection codes, profiles, real infrastructure addresses or private diagnostic data in public issues. If no private channel is available, ask the maintainer for one before disclosing sensitive details.

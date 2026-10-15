# Privacy

No default relay, analytics collector or update service is compiled into this client. The operator supplies a compatible relay address locally. Existing profiles continue using their saved operator configuration.

The relay receives the device's public identity, enrollment authentication metadata, pairing/session requests and traffic timing/volume. Device private keys and plaintext forwarded payloads are not sent to it. Network routing reveals the relay destination to the network and endpoint administrator.

A connection code includes a relay address, provider identity, certificate fingerprint and invitation secrets. Store and transmit it privately. Runtime profiles, local API capabilities, authorization files and backups are not source code and must never be published.

Optional `logging` in the private profile can enable bounded asynchronous diagnostic reporting to an operator-specified HTTPS endpoint with path `/api/front/client-log/report`. It is off for a new profile. Reports contain product version, platform, trace/session references, timing, retry/error classifications and session metadata; not keys, original commands or file contents. Disable it with `logging.enabled: false`. The endpoint operator's privacy rules apply.

Local files retain device identities, keys, authorization, connection settings and audit metadata. Desktop uninstall intentionally preserves these and any separately installed provider. Retiring a device requires deliberate access revocation, service stop and separately authorized handling of retained private data.

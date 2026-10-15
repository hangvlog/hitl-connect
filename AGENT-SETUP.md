# HITL Connect agent operations

Use only devices and accounts authorized by their owner. Preserve all existing identity, trust, pairing and audit data. Do not disable endpoint security or override PowerShell policy.

`hitl-connect-cli agent help` returns supported operations. Use `--dir <private-profile>` consistently. stdout uses the `hitl-connect.agent.v1` JSON schema. Exit 0 means that action/snapshot succeeded; only `loginVerified: true`, `nativeSshExitCode: 0` and the expected `loginIdentity` prove a login.

Provider first use:

```sh
hitl-connect-cli agent allow --relay https://relay.example.invalid --user '<authorized-local-account>' --output '<private-code-file>' --dir '<private-profile>'
```

The operator must supply a real compatible relay locally. Windows installation requests normal UAC. Existing providers preserve their configured address and device identity.

Caller first use:

```sh
hitl-connect-cli agent start --role connect --key-file '<private-code-file>' --dir '<private-profile>' --wait
```

Then use `agent status`, `agent diagnose`, `agent stop`, and `agent start --wait` with that profile. Connection codes remain valid until explicitly disabled or replaced. Never print them or submit profile contents to a public issue.

Treat capacity, offline and data-channel failures as distinct from permission revocation. Do not automatically replay a command after a lost connection: inspect its outcome first.

Local audit includes identity fingerprints, authorization changes and session results, not command/file contents. Audit failure rejects new sessions; an administrator can alter local logs, so they are not tamper-proof.

Do not claim Windows installation, UAC, upgrades, restart or account login was tested merely because compilation or CLI help passed. Report each separately.

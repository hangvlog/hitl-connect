# Multi-agent connections and durable Windows jobs

The caller defaults to 32 active connections plus 128 FIFO pending requests. Pending sockets expire after 15 seconds, including time waiting behind other jobs; the complete connection budget remains 25 seconds. Existing sessions are not evicted. Optional config `capacity` contains `callerConnections` (1-128), `callerQueue` (1-256), `providerConnections` (1-128, default 64), `maxIdleChannels` (1-16, default 16). These are resource budgets, not permission grants.

The v3 provider reserves capacity before pairing. It keeps two idle channels by default, grows to `min(maxIdleChannels, base + active / 4)`, and expires spare idle channels after 10 seconds. The relay advertises its pool limit; absence means the previous limit of four. Control loss cancels only idle workers; established streams retain their own context. Drain includes active durable jobs and cannot kill them to finish an upgrade.

The compatible relay uses bounded round-robin admission between authenticated caller device IDs, FIFO within a caller, 64 waiting requests per caller and 128 per target. The relay budgets are 128 paired sessions, 512 sockets, 192 sockets per device and 16 reserved control sockets. Jobs from multiple agents sharing one caller profile have FIFO admission at that profile; separate caller identities have round-robin relay admission.

## Explicit durable execution

Embedded Windows SSH accepts `hitl-job <base64url-json>` on its authenticated exec channel. Requests are `submit`, `status`, `logs`, `cancel`, with an `id` of 8-64 letters, digits, underscore or dash. Submit requires `command` and `timeoutSeconds` (1-86400). Reuse exactly the same ID and payload after an uncertain response. Conflicting payloads fail `JOB_ID_CONFLICT`. Jobs are scoped to the authenticated device and SSH key and checked against current authorization; revocation cancels active jobs.

Jobs run under the same explicitly approved Windows account and containment as ordinary commands, but their lifetime belongs to the provider, not the submitting SSH connection. Status and exit code persist under the protected provider profile; stdout/stderr are fetched in 64 KiB pages by byte offset. Commands are not written to central logs. There are at most 32 active jobs, 256 retained records per owner, and 64 MiB per output stream. Reaching a limit fails explicitly; history is not automatically deleted. IDs are never automatically replayed. A provider/OS restart interrupts active jobs and projects `interrupted`; completed results remain readable. This does not checkpoint arbitrary programs or resume SFTP offsets.

The private Windows-control Skill exposes `job-submit ID --command ...` (or `--file script.ps1`), `job-status ID`, `job-logs ID --stream stdout --offset 0`, and `job-cancel ID`. Exit code zero for submission only means accepted: wait for `completed` and check the job exit code. Network failure means outcome unknown, never permission to create a fresh job ID. PowerShell scripts must check native process exit codes.

## Acceptance and rollout

Upgrade the compatible relay first after preserving its full registry and revocations outside the deployment instance. Upgrade an idle provider with rollback and unchanged identity/trust, then callers and platform bundles. Keep enterprise devices outside the personal rollout.

Acceptance requires thirty simultaneous held sessions, sixty burst requests, mixed commands/transfers with hashes, control-loss isolation and reconnect, bounded/fair saturation, idle pool shrinkage, durable job deduplication/cancellation/authorization, and a result fetched after disconnecting its submitter. Verify source SHA, running versions, protected profile hashes and rollback artifacts. Local real-process tests cover transport behavior; Windows/WAN acceptance is recorded separately.

# HITL Connect development

This repository is the sole source for the desktop client, CLI, Windows services and installers. Read README.md and relevant tests before changes.

- Preserve device identities, trust, accounts, keys, grants, revocations, audits and user stop state.
- Never commit deployment addresses, profiles, connection codes, private keys, personal diagnostics or local settings. Use reserved example domains in documentation.
- Describe remote access, TCP forwarding and SSH/SFTP capabilities accurately. Do not introduce monitoring evasion or bypass endpoint policy.
- Use versioned source and locked dependencies. Build outside the repository from a clean commit. Never patch compiled artifacts.
- Run the tests relevant to the change, the affected executable entry point and Windows compilation when applicable. Cross compilation is not Windows runtime acceptance.
- This standalone project permits GitHub-hosted Windows builds for code-signing provenance. This exception does not apply to other projects.
- Signing is pending external approval. Never claim an unsigned/test-signed build is a trusted release or silently fall back after signing fails.
- No subagents unless specifically authorized for the current task.

# Code signing policy

Status: **not enrolled or approved for SignPath Foundation signing**. No current build is represented as signed by the Foundation.

Maintainer, reviewer and proposed signing approver: [hangvlog](https://github.com/hangvlog). Contributions from others require maintainer review. All signing participants must enable MFA. Production signing requires manual approval of every request in SignPath.

SignPath Foundation provides a real free open-source signing program, subject to eligibility review, published releases, OSI-approved licensing, project reputation and privacy/security requirements. Its About page says the program is currently operated by SignPath GmbH; it does not establish that a separate independent nonprofit entity already exists. Certificates identify SignPath Foundation and keys remain in its HSM; this is not a downloadable personal PFX certificate.

For its GitHub OSS integration, all jobs leading to a signing request must use GitHub-hosted runners. Artifacts must be uploaded by that workflow and linked to their source commit. A locally built upload or a self-hosted runner is not an equivalent provenance path.

## Planned signed release gate

1. Build from the protected public release commit using locked dependencies and no private deployment configuration.
2. Sign the GUI, CLI and installer helper; verify Authenticode chain and timestamp. Restrict product name, version and explicit filenames in SignPath artifact configuration. Do not re-sign Microsoft system components.
3. Package those exact signed files. For NSIS, arrange signing of its generated uninstaller, then the outer installer; signing the outer EXE alone does not sign its embedded payload. This requires a separately tested multi-stage pipeline.
4. Wait for maintainer approval; signing rejection, missing credentials, invalid signature or timeout must fail publication. Never silently replace a failed signed release with unsigned files.
5. Generate final hashes and manifests **after** signing, verify extraction/install/uninstall, then publish.

Automatic CI produces explicitly named unsigned validation artifacts only. The manual `sign-portable.yml` workflow and `signing/windows-binaries.xml` provide a fail-closed integration entry for GUI/CLI/helper signing after actual enrollment; it is not executed or accepted as a signed release yet. This entry has no automatic release upload; it does not implement or claim the above signed NSIS pipeline. Before enabling signing, obtain Foundation acceptance and configure the organization, project, allowed refs, artifact configuration, MFA, approvers and least-privilege submission credentials. Add the required Foundation attribution only once actually granted.

[Privacy](PRIVACY.md)

Official references checked 2026-10-15:
- https://signpath.org/about.html
- https://signpath.org/terms.html
- https://signpath.org/apply
- https://docs.signpath.io/trusted-build-systems/github
- https://docs.signpath.io/artifact-configuration/reference

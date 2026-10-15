# Windows usage

Use a 64-bit Windows build. Test artifacts are unsigned; review their source and hashes. A code signature does not override organization policy.

1. Start `HITL-Connect.exe`. It opens a loopback-only browser panel.
2. To provide access, enter your own compatible HTTPS relay address and choose the local account and privilege level. The explicit Allow action uses normal Windows UAC to install a background service.
3. Share the generated connection code privately with an authorized caller. The caller selects Connect and pastes it.
4. Check the actual remote account login result. A listening port or connected relay alone is not proof of successful login.

The default embedded SSH mode requires the account to remain logged in; locking the screen is supported, logging out is a different state. It does not install system OpenSSH or change PowerShell execution policy.

Stop preserves configuration. Disable/renew code revokes access under that code; renewal may terminate those active sessions. Closing the browser does not stop the service. Use the controls intentionally.

Keep profiles, private keys, connection codes, local settings and audit records private. Back them up before upgrades. Never erase an identity to fix a temporary network error.

The optional NSIS desktop installer creates client shortcuts and an uninstall entry. It does not grant remote access or install a provider automatically. Uninstalling this desktop client preserves independently authorized services and profiles; disable access and stop the provider first when retiring a device.

Service upgrades drain active sessions and may defer instead of interrupting them. Unknown service state, endpoint-protection rejection or inaccessible configuration must be diagnosed rather than bypassed.

# Windows packaging

Use Python 3.12+, the Go toolchain pinned by CI and NSIS 3.13. Build from a clean committed checkout with output outside the repository:

```sh
python build-windows-release.py ../windows-release 2026.10.15-agent.1 --makensis '<path-to-NSIS-3.13-makensis.exe>'
```

`build-windows-binaries.py` builds the GUI, CLI and installer helper. `build-windows-release.py` also builds the desktop NSIS installer, generated uninstaller and portable ZIP. `--system-ssh-installer` is an explicit advanced existing-profile migration target, not the default client setup.

These current packaging scripts produce **unsigned** artifacts and say so in their manifests. The [code signing policy](../CODE-SIGNING.md) describes the pending signed pipeline; do not substitute the scripts for that gate.

Desktop setup manages only client files, shortcuts and an uninstall entry. It does not automatically enable remote access. The helper checks file occupancy; consent to close a same-user old panel does not authorize interruption of unrelated commands or providers. Uninstall preserves private profiles and separately installed services.

Windows validation must distinguish compilation, help/configuration tests, installation, interactive UAC, actual account login and service restart. No earlier private device evidence is imported as acceptance of these public builds.

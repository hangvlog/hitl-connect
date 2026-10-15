#!/usr/bin/env bash
set -euo pipefail
# NSIS on macOS requires a UTF-8 locale for Unicode installer text.
export LANG=en_GB.UTF-8 LC_ALL=en_GB.UTF-8
cd "$(dirname "$0")"
out="${1:?usage: build-windows-installer.sh /absolute/output/directory}"
case "$out" in /*) ;; *) printf 'output directory must be absolute\n' >&2; exit 2;; esac
version=2026.10.10-agent.26
command -v makensis >/dev/null || { printf 'NSIS 3.13 is required (brew install makensis).\n' >&2; exit 2; }
nsis_version="$(makensis -VERSION)"
[[ "$nsis_version" == v3.13 ]] || { printf 'Expected NSIS v3.13; got %s\n' "$nsis_version" >&2; exit 2; }
./build-windows-kit.sh "$out" "$version"
installer="$out/HITL-Connect-Setup-$version.exe"
numeric_version="${version/-agent./.}"
makensis -WX -V2 "-DPACKAGE_DIR=$out/HITL-Connect-Windows" "-DHELPER_FILE=$out/HITL-Connect-Installer-Helper.exe" "-DOUTPUT_FILE=$installer" "-DVERSION=$version" "-DNUMERIC_VERSION=$numeric_version" installer/windows.nsi
python3 - "$out" "$installer" "$nsis_version" <<'PY'
import hashlib,json,pathlib,sys
out,installer=map(pathlib.Path,sys.argv[1:3])
manifest=json.loads((out/'HITL-Connect-Windows/manifest.json').read_text())
data=installer.read_bytes()
assert data[:2]==b'MZ'
record={'product':'HITL Connect','version':manifest['version'],'sourceCommit':manifest['sourceCommit'],
    'sourceRepository':manifest['sourceRepository'],'sourceDirectory':manifest['sourceDirectory'],
    'installer':{'file':installer.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'format':'NSIS','compiler':sys.argv[3],'authenticode':'unsigned'},
    'scope':{'perUserClient':True,'autoLaunch':False,'serviceInstallDuringSetup':False,'preservesExistingProfiles':True,'uninstallRemovesSeparatelyAuthorizedService':False,'closeSameUserDesktopPanelAfterConsent':True,'skipLockedFiles':False},
    'installerHelper':{'sha256':hashlib.sha256((out/'HITL-Connect-Installer-Helper.exe').read_bytes()).hexdigest()},
    'payload':manifest['files'],'validation':{'windowsInstallerRuntimeVerified':False,'enterpriseKasperskyAccepted':False}}
(out/'installer-manifest.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(record,ensure_ascii=False,indent=2))
PY

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
out="${1:?usage: build-windows-kit.sh /absolute/output/directory [version]}"
version="${2:-2026.10.10-agent.25}"
evidence="${3:-}"
case "$out" in /*) ;; *) printf 'output directory must be absolute\n' >&2; exit 2;; esac
case "$version" in *[!a-zA-Z0-9._+-]*) printf 'invalid version\n' >&2; exit 2;; esac
if [[ -n "$(git status --porcelain -- .)" ]]; then
  printf 'Commit the client source before packaging; the manifest must identify the actual build.\n' >&2
  exit 2
fi
revision="$(git rev-parse HEAD)"
kit="$out/HITL-Connect-Windows"
mkdir -p "$kit"
python3 build-windows-binaries.py "$kit" "$version" --installer-helper
cp AGENT-SETUP.md "$kit/AGENTS.md"
cp README-WINDOWS.md "$kit/README.md"
cp SECURITY-REVIEW.md "$kit/SECURITY-REVIEW.md"
cp Verify-Package.ps1 "$kit/Verify-Package.ps1"
cp LICENSE NOTICE THIRD-PARTY-LICENSES.txt PRIVACY.md CODE-SIGNING.md "$kit/"
python3 - "$out" "$version" "$revision" "$evidence" <<'PY'
import hashlib,json,pathlib,struct,sys,zipfile
out=pathlib.Path(sys.argv[1]); kit=out/'HITL-Connect-Windows'
files={}
for name in ['HITL-Connect.exe','hitl-connect-cli.exe','HITL-Connect.ico','AGENTS.md','README.md','SECURITY-REVIEW.md','Verify-Package.ps1','LICENSE','NOTICE','THIRD-PARTY-LICENSES.txt','PRIVACY.md','CODE-SIGNING.md']:
    data=(kit/name).read_bytes()
    files[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    if name.endswith('.exe'):
        pe=struct.unpack_from('<I',data,0x3c)[0]
        machine=struct.unpack_from('<H',data,pe+4)[0]
        subsystem=struct.unpack_from('<H',data,pe+24+68)[0]
        assert data[pe:pe+4]==b'PE\0\0' and machine==0x8664
        assert subsystem==(2 if name=='HITL-Connect.exe' else 3)
        files[name]['peSubsystem']='windows-gui' if subsystem==2 else 'windows-console'
checks=['restrictedPolicyPreserved','freshProfileInstallVerified','repeatInstallVerified','existingProfileUpgradeVerified',
        'newDeviceAuthorizationVerified','concurrentLoginVerified','fileRoundtripVerified','serviceRestartVerified',
        'identityKeyCodePreserved','hostTrustPreserved','backupsVerified','revocationVerified',
        'embeddedSSHVerified','systemSSHUnchanged','administratorModeVerified','standardModeVerified','auditVerified',
        'goRacePassed','goVetPassed','clientE2EPassed','windowsWithoutOpenSSHVerified','uacInteractiveVerified',
        'preLogonExecutionSupported','ptySupported']
validation={k:False for k in checks}
if sys.argv[4]:
    evidence=json.loads(pathlib.Path(sys.argv[4]).read_text())
    assert evidence['schemaVersion']=='hitl-connect.embedded-ssh-validation.v1'
    assert evidence['sourceCommit']==sys.argv[3], 'verification must match the packaged source commit'
    assert all(type(evidence[k]) is bool for k in checks)
    validation={k:evidence[k] for k in checks}
    allowed=['schemaVersion','sourceCommit','windowsVersion','policyBefore','policyAfter','loginIdentity','nativeSshExitCodes',*checks]
    data=(json.dumps({k:evidence[k] for k in allowed if k in evidence},ensure_ascii=False,indent=2)+'\n').encode()
    (kit/'validation.json').write_bytes(data)
    files['validation.json']={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
manifest={'product':'HITL Connect','version':sys.argv[2],'sourceCommit':sys.argv[3],
    'sourceRepository':'https://github.com/hangvlog/hitl-connect.git','sourceDirectory':'.',
    'platform':'windows-amd64','agentSchema':'hitl-connect.agent.v1',
    'agentEntry':['hitl-connect-cli.exe','agent','help'],'agentInstructions':'AGENTS.md',
    'files':files,'security':{'authenticode':'unsigned','setupEngine':'windows-native-embedded-ssh','powerShellRequired':False,
    'nativeInterfaces':['NetUserGetInfo/SID','SCM','Windows security descriptors','WTS account tokens','Job Objects'],
    'sshServer':'HITL Connect','systemOpenSSHRequired':False,'sshBanner':'SSH-2.0-HITL_Connect','accountSessionRequired':True,
    'executionPolicyOverride':False,'vendorFalsePositiveConfirmed':False,'affectedEndpointRetested':False,'reviewGuide':'SECURITY-REVIEW.md'},
    'validation':{'windowsCrossCompile':True,**validation}}
(kit/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
archive=out/('HITL-Connect-Windows-'+sys.argv[2]+'.zip')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for name in [*files,'manifest.json']:
        z.write(kit/name,'HITL-Connect-Windows/'+name)
print(json.dumps({'archive':str(archive),'bytes':archive.stat().st_size,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'sourceCommit':sys.argv[3]},ensure_ascii=False))
PY

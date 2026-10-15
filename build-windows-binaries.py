#!/usr/bin/env python3
"""Build branded Windows executables from a clean, committed source snapshot."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

source = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output')
parser.add_argument('version')
parser.add_argument('--go', default='go')
parser.add_argument('--installer-helper', action='store_true')
args = parser.parse_args()
match = re.fullmatch(r'(\d{4})\.(\d{2})\.(\d{2})-agent\.(\d+)', args.version)
if not match or any(int(v) > 65535 for v in match.groups()):
    parser.error('Version must be YYYY.MM.DD-agent.N within Windows version limits')
output = Path(args.output).resolve()
repo = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=source, text=True).strip())
if output == repo or repo in output.parents:
    parser.error('Build output must be outside the repository')
if subprocess.check_output(['git', 'status', '--porcelain', '--', '.'], cwd=source).strip():
    parser.error('Commit client changes before building')
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
relative = source.relative_to(repo).as_posix()
archive = subprocess.check_output(['git', 'archive', 'HEAD' if relative == '.' else 'HEAD:'+relative], cwd=repo)
native = os.environ.copy()
native.pop('GOOS', None)
native.pop('GOARCH', None)
native['CGO_ENABLED'] = '0'
output.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='hitl-windows-build-', dir=output.parent) as staging:
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        bundle.extractall(staging, filter='data')
    checkout = Path(staging)
    icon = output/'HITL-Connect.ico'
    def run(command, env=native):
        subprocess.run(command, cwd=checkout, env=env, check=True)
    run([args.go, 'run', './internal/windows-branding', '--out', str(icon)])
    fixed = dict(zip(('Major', 'Minor', 'Patch', 'Build'), map(int, match.groups())))
    target = {**native, 'GOOS':'windows', 'GOARCH':'amd64'}
    programs = [
        ('HITL-Connect.exe', 'HITL Connect', True, '.'),
        ('hitl-connect-cli.exe', 'HITL Connect CLI', False, '.'),
    ]
    if args.installer_helper:
        programs.append(('HITL-Connect-Installer-Helper.exe', 'HITL Connect Setup Helper', False, 'internal/installer-helper'))
    for name, description, gui, package in programs:
        resource = {
            'FixedFileInfo': {'FileVersion':fixed, 'ProductVersion':fixed, 'FileFlagsMask':'3f', 'FileOS':'040004', 'FileType':'01'},
            'StringFileInfo': {
                'CompanyName':'HITL Connect contributors', 'ProductName':'HITL Connect',
                'FileDescription':description, 'InternalName':Path(name).stem,
                'OriginalFilename':name, 'FileVersion':args.version, 'ProductVersion':args.version,
                'Comments':'Source: github.com/hangvlog/hitl-connect '+commit,
            },
            'VarFileInfo':{'Translation':{'LangID':'0409','CharsetID':'04B0'}},
            'IconPath':str(icon),
        }
        config = checkout/'windows-versioninfo.json'
        config.write_text(json.dumps(resource), encoding='utf-8')
        resource_file = checkout/package/'resource_windows_amd64.syso'
        run([args.go, 'tool', 'goversioninfo', '-64', '-o', str(resource_file), str(config)])
        flags = '-s -w '+('-H=windowsgui ' if gui else '')+'-X main.guiVersion='+args.version+'+'+commit
        destination = output/name if package == '.' else output.parent/name
        run([args.go, 'build', '-buildvcs=false', '-trimpath', '-ldflags', flags, '-o', str(destination), './'+package], target)
print(json.dumps({'sourceCommit':commit,'version':args.version,'output':str(output)}))

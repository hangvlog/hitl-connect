#!/usr/bin/env python3
"""Native Windows build entry for branded portable and NSIS client releases."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('output')
parser.add_argument('version')
parser.add_argument('--go', default='go')
parser.add_argument('--makensis', required=True)
parser.add_argument('--system-ssh-installer', action='store_true', help='Build the opt-in existing-profile boot service installer')
args=parser.parse_args()
source=Path(__file__).resolve().parent
output=Path(args.output).resolve()
kit=output/'HITL-Connect-Windows'
compiler=subprocess.check_output([args.makensis, '/VERSION'], text=True).strip()
if compiler!='v3.13':
    parser.error('NSIS v3.13 is required')
subprocess.run([sys.executable,str(source/'build-windows-binaries.py'),str(kit),args.version,'--go',args.go,'--installer-helper'],check=True)
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
for src,dest in [('AGENT-SETUP.md','AGENTS.md'),('README-WINDOWS.md','README.md'),('SECURITY-REVIEW.md','SECURITY-REVIEW.md'),('Verify-Package.ps1','Verify-Package.ps1'),('LICENSE','LICENSE'),('NOTICE','NOTICE'),('THIRD-PARTY-LICENSES.txt','THIRD-PARTY-LICENSES.txt'),('PRIVACY.md','PRIVACY.md'),('CODE-SIGNING.md','CODE-SIGNING.md')]:
    shutil.copyfile(source/src,kit/dest)
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value): path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
files={path.name:{'bytes':path.stat().st_size,'sha256':digest(path)} for path in kit.iterdir() if path.is_file() and path.name!='manifest.json'}
manifest={'product':'HITL Connect','version':args.version,'sourceRepository':'https://github.com/hangvlog/hitl-connect.git','sourceDirectory':'.','sourceCommit':commit,'platform':'windows-amd64','files':files,'agentSchema':'hitl-connect.agent.v1','agentEntry':['hitl-connect-cli.exe','agent','help'],'agentInstructions':'AGENTS.md','security':{'authenticode':'unsigned','systemOpenSSHModified':False},'validation':{'windowsBuild':True,'runtimeAcceptance':False}}
save(kit/'manifest.json',manifest)
installer=output/('HITL-Connect-Setup-'+args.version+'.exe')
subprocess.run([args.makensis,'/WX','/V2','/INPUTCHARSET','UTF8','/DPACKAGE_DIR='+str(kit),'/DHELPER_FILE='+str(output/'HITL-Connect-Installer-Helper.exe'),'/DOUTPUT_FILE='+str(installer),'/DVERSION='+args.version,'/DNUMERIC_VERSION='+args.version.replace('-agent.','.'),str(source/'installer/windows.nsi')],check=True)
archive=output/('HITL-Connect-Windows-'+args.version+'.zip')
with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as bundle:
    for name in [*files,'manifest.json']: bundle.write(kit/name,'HITL-Connect-Windows/'+name)
with zipfile.ZipFile(archive) as bundle:
    for name,record in files.items():
        assert hashlib.sha256(bundle.read('HITL-Connect-Windows/'+name)).hexdigest()==record['sha256']
record={'product':'HITL Connect','version':args.version,'sourceCommit':commit,'compiler':compiler,'installer':{'file':installer.name,'bytes':installer.stat().st_size,'sha256':digest(installer),'authenticode':'unsigned'},'helper':{'file':'HITL-Connect-Installer-Helper.exe','sha256':digest(output/'HITL-Connect-Installer-Helper.exe')},'portable':{'file':archive.name,'bytes':archive.stat().st_size,'sha256':digest(archive)},'payload':files,'scope':'Per-user desktop client. Does not upgrade or uninstall independently deployed providers, profiles or system OpenSSH.'}
save(output/'installer-manifest.json',record)
print(json.dumps(record,ensure_ascii=False))
if args.system_ssh_installer:
    boot=output/('HITL-Connect-Boot-Setup-'+args.version+'.exe')
    subprocess.run([args.makensis,'/WX','/V2','/INPUTCHARSET','UTF8','/DPACKAGE_DIR='+str(kit),'/DOUTPUT_FILE='+str(boot),'/DVERSION='+args.version,'/DNUMERIC_VERSION='+args.version.replace('-agent.','.'),str(source/'installer/system-ssh.nsi')],check=True)
    save(output/'system-ssh-installer-manifest.json',{'product':'HITL Connect boot service','version':args.version,'sourceRepository':'https://github.com/hangvlog/hitl-connect.git','sourceCommit':commit,'file':boot.name,'sha256':digest(boot),'bytes':boot.stat().st_size,'runtimeAcceptance':False,'scope':'Explicit existing-profile migration; creates an automatic relay service, preserves SSH identity, sets hitlconnect.exe alias. Does not reboot Windows.'})

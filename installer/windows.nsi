Unicode true
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

!ifndef PACKAGE_DIR
  !error "PACKAGE_DIR is required"
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE is required"
!endif
!ifndef VERSION
  !error "VERSION is required"
!endif

Name "HITL Connect"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\HITL Connect"
InstallDirRegKey HKCU "Software\HITLConnect\DesktopInstaller" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
AllowSkipFiles off
ShowInstDetails show
ShowUninstDetails show
!ifndef NUMERIC_VERSION
  !error "NUMERIC_VERSION is required"
!endif
!ifndef HELPER_FILE
  !error "HELPER_FILE is required"
!endif
VIProductVersion "${NUMERIC_VERSION}"
!define MUI_ICON "${PACKAGE_DIR}\HITL-Connect.ico"
!define MUI_UNICON "${PACKAGE_DIR}\HITL-Connect.ico"
VIAddVersionKey /LANG=2052 "CompanyName" "HITL Connect contributors"
VIAddVersionKey /LANG=2052 "ProductName" "HITL Connect"
VIAddVersionKey /LANG=2052 "FileDescription" "HITL Connect Windows client setup"
VIAddVersionKey /LANG=2052 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=2052 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=2052 "LegalCopyright" "HITL Connect contributors"

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "安装 HITL Connect"
!define MUI_WELCOMEPAGE_TEXT "此向导安装 HITL Connect 客户端、开始菜单入口和卸载程序。$\r$\n$\r$\n安装完成后，从开始菜单打开 HITL Connect，在界面中明确授权后才开启远程访问。$\r$\n$\r$\n安装向导不启动客户端、不创建远程访问服务、不修改系统防护或 PowerShell 策略。现有账号、身份、私钥、连接码和配置保留。$\r$\n$\r$\n当前安装包未数字签名；不能保证通过企业终端防护。"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "HITL Connect 客户端安装完成"
!define MUI_FINISHPAGE_TEXT "请从开始菜单打开 HITL Connect。$\r$\n$\r$\n首次提供远程访问时，界面会说明账号和权限，并请求 Windows 授权。安装完成不表示远程访问已开启。$\r$\n$\r$\n现有后台服务及资料保持原状。若需停用已有访问，请在界面中停用连接码并停止连接。"
!insertmacro MUI_PAGE_FINISH

!define MUI_UNCONFIRMPAGE_TEXT_TOP "此操作仅卸载 HITL Connect 客户端和快捷方式，保留账号、身份、私钥、连接码、审计和配置备份。$\r$\n$\r$\n已单独授权安装的 Windows 后台服务不会被此客户端卸载器删除。若要撤销远程访问，请先在 HITL Connect 界面中停用连接码并停止连接，再卸载客户端。"
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  SetShellVarContext current
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "此安装包需要 64 位 Windows。" /SD IDOK
    Abort
  ${EndIf}
FunctionEnd

Function PrepareDesktopUpgrade
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=HITL-Connect-Installer-Helper.exe "${HELPER_FILE}"
  prepare_check:
  nsExec::ExecToStack /TIMEOUT=15000 '"$PLUGINSDIR\HITL-Connect-Installer-Helper.exe" --dir "$INSTDIR\."'
  Pop $0
  Pop $1
  StrCmp $0 "0" prepare_done
  StrCmp $0 "10" prepare_consent prepare_blocked
  prepare_consent:
  IfSilent prepare_cancel
  MessageBox MB_OKCANCEL|MB_ICONINFORMATION "检测到此安装目录的旧 HITL Connect 客户端仍在运行。$\r$\n$\r$\n点击确定后，安装器将结束旧客户端并自动继续。其他安装目录、正在执行的命令和后台服务不会被自动结束，账号、连接码及配置保留。" IDOK prepare_close IDCANCEL prepare_cancel
  prepare_close:
  nsExec::ExecToStack /TIMEOUT=15000 '"$PLUGINSDIR\HITL-Connect-Installer-Helper.exe" --dir "$INSTDIR\." --close-panels'
  Pop $0
  Pop $1
  StrCmp $0 "0" prepare_done
  prepare_blocked:
  DetailPrint "安装前检查未通过：$1"
  IfSilent prepare_failed
  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "安装前检查未通过，尚未替换客户端文件。$\r$\n$\r$\n$1$\r$\n$\r$\n请先完成占用文件的操作，或核对写入权限及防护记录，然后点击重试。" IDRETRY prepare_check IDCANCEL prepare_failed
  prepare_failed:
  SetErrorLevel 20
  Quit
  prepare_cancel:
  SetErrorLevel 10
  Quit
  prepare_done:
FunctionEnd

Section "HITL Connect 客户端" Main
  Call PrepareDesktopUpgrade
  SetOutPath "$INSTDIR"
  SetOverwrite on
  ; Explicit inventory: never include developer profiles, credentials or logs.
  File "${PACKAGE_DIR}\HITL-Connect.exe"
  File "${PACKAGE_DIR}\hitl-connect-cli.exe"
  File "${PACKAGE_DIR}\HITL-Connect.ico"
  File "${PACKAGE_DIR}\AGENTS.md"
  File "${PACKAGE_DIR}\README.md"
  File "${PACKAGE_DIR}\SECURITY-REVIEW.md"
  File "${PACKAGE_DIR}\Verify-Package.ps1"
  File "${PACKAGE_DIR}\manifest.json"
  File "${PACKAGE_DIR}\LICENSE"
  File "${PACKAGE_DIR}\NOTICE"
  File "${PACKAGE_DIR}\THIRD-PARTY-LICENSES.txt"
  File "${PACKAGE_DIR}\PRIVACY.md"
  File "${PACKAGE_DIR}\CODE-SIGNING.md"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\HITL Connect"
  ; The provider owns HITL Connect.lnk. This installer owns only the explicitly
  ; named client shortcut, so updating/uninstalling it cannot erase the provider.
  CreateShortcut "$SMPROGRAMS\HITL Connect\HITL Connect 客户端.lnk" "$INSTDIR\HITL-Connect.exe" "" "$INSTDIR\HITL-Connect.ico" 0 SW_SHOWNORMAL "" "HITL Connect 客户端面板"
  CreateShortcut "$SMPROGRAMS\HITL Connect\卸载客户端.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\HITL-Connect.ico" 0 SW_SHOWNORMAL "" "卸载 HITL Connect 客户端"
  WriteRegStr HKCU "Software\HITLConnect\DesktopInstaller" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "DisplayName" "HITL Connect 客户端"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "Publisher" "HITL Connect contributors"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "DisplayIcon" '"$INSTDIR\HITL-Connect.exe",0'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "URLInfoAbout" "https://github.com/hangvlog/hitl-connect"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop" "EstimatedSize" $0
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  ; Remove only the installer inventory. User data and independently installed
  ; provider services are outside this per-user client's ownership.
  ClearErrors
  Delete "$INSTDIR\HITL-Connect.exe"
  Delete "$INSTDIR\hitl-connect-cli.exe"
  Delete "$INSTDIR\HITL-Connect.ico"
  IfErrors 0 +3
    MessageBox MB_ICONSTOP "客户端文件仍在使用或无法删除，请关闭从此目录启动的客户端后重试。卸载登记已保留。" /SD IDOK
    Abort
  Delete "$INSTDIR\AGENTS.md"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\SECURITY-REVIEW.md"
  Delete "$INSTDIR\Verify-Package.ps1"
  Delete "$INSTDIR\manifest.json"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\NOTICE"
  Delete "$INSTDIR\THIRD-PARTY-LICENSES.txt"
  Delete "$INSTDIR\PRIVACY.md"
  Delete "$INSTDIR\CODE-SIGNING.md"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\HITL Connect\HITL Connect 客户端.lnk"
  Delete "$SMPROGRAMS\HITL Connect\卸载客户端.lnk"
  RMDir "$SMPROGRAMS\HITL Connect"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HITLConnectDesktop"
  DeleteRegKey HKCU "Software\HITLConnect\DesktopInstaller"
SectionEnd

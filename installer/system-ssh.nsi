Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"
Name "HITL Connect 开机连接"
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\HITL Connect\${VERSION}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
AllowSkipFiles off
ShowInstDetails show
VIProductVersion "${NUMERIC_VERSION}"
VIAddVersionKey /LANG=2052 "ProductName" "HITL Connect"
VIAddVersionKey /LANG=2052 "FileDescription" "HITL Connect 开机连接安装程序"
VIAddVersionKey /LANG=2052 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=2052 "LegalCopyright" "HITL Connect contributors"
!define MUI_ICON "${PACKAGE_DIR}\HITL-Connect.ico"
!define MUI_WELCOMEPAGE_TITLE "安装 HITL Connect 开机连接"
!define MUI_WELCOMEPAGE_TEXT "保留已有账号、密钥和连接码，将 SSH 服务名设为 hitlconnect-server，SSH 和文件传输进程均设为 hitlconnect.exe，并安装开机连接服务。$\r$\n$\r$\n安装默认等待现有远程会话结束；仍有传输或无法确认状态时会推迟升级，不强制断开。仅用于已有系统 SSH 配置的电脑；安装不会重启 Windows。"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "HITL Connect 已安装"
!define MUI_FINISHPAGE_TEXT "开机连接服务已启动。可从桌面打开管理页。$\r$\n$\r$\n安装结果不代表云端中继或实际整机重启已验收；验证记录另附。"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "SimpChinese"
Var ExistingProfile
Var Interrupted
Function .onInit
 SetShellVarContext current
 ${IfNot} ${RunningX64}
  Abort
 ${EndIf}
 StrCpy $ExistingProfile "$APPDATA\hitl-connect"
 ${GetParameters} $R0
 ${GetOptions} $R0 "/PROFILE=" $R1
 StrCmp $R1 "" +2
 StrCpy $ExistingProfile $R1
 StrCpy $Interrupted ""
 ClearErrors
 ${GetOptions} $R0 "/INTERRUPT" $R1
 IfErrors +2
 StrCpy $Interrupted "--interrupt-sessions"
FunctionEnd
Section
 SetOutPath "$INSTDIR"
 SetOverwrite off
 File "${PACKAGE_DIR}\HITL-Connect.exe"
 File "${PACKAGE_DIR}\hitl-connect-cli.exe"
 File "${PACKAGE_DIR}\HITL-Connect.ico"
 File "${PACKAGE_DIR}\manifest.json"
 File "${PACKAGE_DIR}\LICENSE"
 File "${PACKAGE_DIR}\NOTICE"
 File "${PACKAGE_DIR}\THIRD-PARTY-LICENSES.txt"
 File "${PACKAGE_DIR}\PRIVACY.md"
 File "${PACKAGE_DIR}\CODE-SIGNING.md"
 nsExec::ExecToStack /TIMEOUT=120000 '"$INSTDIR\HITL-Connect.exe" install-system-ssh --dir "$ExistingProfile" $Interrupted'
 Pop $0
 Pop $1
 StrCmp $0 "0" installed
 DetailPrint "安装未完成：$1"
 SetErrorLevel 20
 Abort
 installed:
 ; Keep the previous login launcher recoverable, outside the Startup folder.
 IfFileExists "$SMSTARTUP\HITL Connect Startup.lnk" 0 startup_migrated
 CreateDirectory "$ExistingProfile\startup-backup"
 ClearErrors
 Rename "$SMSTARTUP\HITL Connect Startup.lnk" "$ExistingProfile\startup-backup\HITL Connect Startup-${VERSION}.lnk"
 IfErrors 0 startup_migrated
 DetailPrint "后台服务已安装，但旧登录启动入口迁移失败。请检查后再重启。"
 SetErrorLevel 21
 Abort
 startup_migrated:
 CreateDirectory "$SMPROGRAMS\HITL Connect"
 CreateShortcut "$DESKTOP\HITL Connect（系统 SSH）.lnk" "$INSTDIR\HITL-Connect.exe" 'gui --dir "$ExistingProfile"' "$INSTDIR\HITL-Connect.ico"
 CreateShortcut "$SMPROGRAMS\HITL Connect\HITL Connect 开机连接.lnk" "$INSTDIR\HITL-Connect.exe" 'gui --dir "$ExistingProfile"' "$INSTDIR\HITL-Connect.ico"
SectionEnd

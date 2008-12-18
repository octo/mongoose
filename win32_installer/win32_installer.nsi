!define VERSION "2.2"
!define MENUDIR "Mongoose web server"
!define	SVC "Mongoose ${VERSION}"

OutFile mongoose-${VERSION}.install.exe
Name "Mongoose ${VERSION}"
InstallDir C:\mongoose-${VERSION}

Page components
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Mongoose files (required)"
  SectionIn RO
  SetOutPath $INSTDIR
  File ..\mongoose.exe
  File ..\mongoose.dll
  File ..\mongoose.lib
  File mongoose.conf
  File README.txt
  WriteUninstaller uninstall.exe
SectionEnd

Section "SSL files"
  File libssl32.dll
  File libeay32.dll
  File ssl_cert.pem
  FileOpen $0 mongoose.conf a
  FileSeek $0 0 END
  FileWrite $0 "ssl_cert $INSTDIR\ssl_cert.pem"
  FileClose $0
SectionEnd

Section "Run Mongoose as service"
  ExecWait 'sc create "${SVC}" binpath= $INSTDIR\mongoose.exe start= auto depend= Tcpip'
  ExecWait 'sc description "${SVC}" "Web server"'
  ExecWait 'sc start "${SVC}"'
SectionEnd

Section "Create menu shortcuts"
  CreateDirectory "$SMPROGRAMS\${MENUDIR}"
  CreateShortCut "$SMPROGRAMS\${MENUDIR}\Start in console.lnk" "$INSTDIR\mongoose.exe"
  CreateShortCut "$SMPROGRAMS\${MENUDIR}\Edit config.lnk" "notepad" "$INSTDIR\mongoose.conf"
  CreateShortCut "$SMPROGRAMS\${MENUDIR}\Stop service.lnk" "sc" 'stop "Mongoose ${VERSION}"'
  CreateShortCut "$SMPROGRAMS\${MENUDIR}\Start service.lnk" "sc" 'start "Mongoose ${VERSION}"'
  CreateShortCut "$SMPROGRAMS\${MENUDIR}\uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  ExecWait 'sc stop "${SVC}"'
  ExecWait 'sc delete "${SVC}"'
  Delete "$INSTDIR\*.*"
  Delete "$SMPROGRAMS\mongoose\*.*"
  RMDir "$SMPROGRAMS\mongoose"
  RMDir "$INSTDIR"
SectionEnd

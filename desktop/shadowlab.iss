[Setup]
AppName=ShadowLab
AppVersion=2.1.0
DefaultDirName={autopf}\ShadowLab
DefaultGroupName=ShadowLab
OutputBaseFilename=ShadowLab-Setup
Compression=lzma
SolidCompression=yes
SetupIconFile=..\static\shadowlab.ico

[Files]
Source: "..\dist\ShadowLab\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ShadowLab"; Filename: "{app}\ShadowLab.exe"
Name: "{autodesktop}\ShadowLab"; Filename: "{app}\ShadowLab.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"

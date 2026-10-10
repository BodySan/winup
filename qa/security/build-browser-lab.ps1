param([string]$Output = 'C:\WinUp\test\audit\candidate',[string]$Source)
$ErrorActionPreference = 'Stop'
$src = if($Source) { [IO.Path]::GetFullPath($Source) } else { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\src')) }
New-Item -ItemType Directory -Force $Output | Out-Null
& "$src\updates\prepare.ps1"
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$common = @('/nologo','/platform:anycpu','/langversion:5','/unsafe+',"/win32manifest:$src\app.manifest",
  "/r:$src\lib\KeePassLib.dll",'/r:System.Windows.Forms.dll','/r:System.Drawing.dll',
  '/r:System.Web.Extensions.dll','/r:System.Security.dll','/r:System.IO.Compression.dll',
  '/r:System.IO.Compression.FileSystem.dll',"/resource:$src\defaults.json,defaults.json",
  "/resource:$src\help.html,help.html","/resource:$src\THIRD-PARTY.md,THIRD-PARTY.md",
  "/resource:$src\lib\KeePassLib.dll,KeePassLib.dll")
foreach ($file in Get-ChildItem "$src\browser" -File) {
  if ($file.Extension -in '.json','.js','.html','.png' -or $file.Name -eq 'winup-firefox.xpi') { $common += "/resource:$($file.FullName),browser/$($file.Name)" }
}
$sources = @((Get-ChildItem $src -Filter '*.cs').FullName) + "$src\Properties\AssemblyInfo.cs"
$common += "/resource:$src\file-engine\file-engine.zip,file-engine.zip", "/resource:$src\file-engine\file-engine.json,file-engine.json"
$common += "/resource:$src\file-engine\winfsp.msi,winfsp.msi"
foreach ($module in 'WinUp.PasskeyEngine','BouncyCastle.Cryptography','CBOR','Numbers') { $common += "/resource:$src\lib\$module.dll,$module.dll" }
$common += "/r:$src\lib\WinUp.PasskeyEngine.dll"
$common += "/resource:$src\public-suffix-list.dat,public-suffix-list.dat"
$common += "/resource:$src\updates\components.json,components.json","/resource:$src\updates\publisher.xml,component-publisher.xml"
foreach($file in Get-ChildItem "$src\licenses" -File) { $common += "/resource:$($file.FullName),licenses/$($file.Name)" }
foreach($name in 'WinUp.Passkeys.msix','WinUp.Passkeys.cer','package.json','Logo.png','setup.ps1','WinUp.PasskeyProvider.exe'){$common += "/resource:$src\system-passkeys\$name,system-passkeys/$name"}
New-Item -ItemType Directory -Force "$Output\browser-lab" | Out-Null
& $csc @common '/target:winexe' '/main:WinUp.FeatureUiHarness' "/out:$Output\browser-lab\WinUp.exe" @sources "$PSScriptRoot\FeatureUiHarness.cs"
if($LASTEXITCODE){throw 'Browser lab build failed'}
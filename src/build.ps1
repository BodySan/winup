param([string]$Output=(Join-Path $PSScriptRoot '..\WinUp.exe'),[string]$Source,[string]$ExtraSource,[string]$EntryPoint)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Output))) | Out-Null
$src=if($Source) { [IO.Path]::GetFullPath($Source) } else { $PSScriptRoot }
& "$PSScriptRoot\updates\prepare.ps1" -Source $src
$csc="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if(!(Test-Path $csc)) { $csc="$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
$args=@('/nologo','/target:winexe','/platform:anycpu','/langversion:5','/unsafe+',"/win32manifest:$src\app.manifest","/out:$Output",
    "/r:$src\lib\KeePassLib.dll","/r:$src\lib\WinUp.PasskeyEngine.dll",'/r:System.Windows.Forms.dll','/r:System.Drawing.dll',
    '/r:System.Web.Extensions.dll','/r:System.Security.dll','/r:System.IO.Compression.dll','/r:System.IO.Compression.FileSystem.dll')
foreach($name in 'defaults.json','help.html','THIRD-PARTY.md','public-suffix-list.dat') { $args += "/resource:$src\$name,$name" }
$args += "/resource:$src\updates\components.json,components.json","/resource:$src\updates\publisher.xml,component-publisher.xml"
foreach($name in 'KeePassLib','WinUp.PasskeyEngine','BouncyCastle.Cryptography','CBOR','Numbers') { $args += "/resource:$src\lib\$name.dll,$name.dll" }
foreach($file in Get-ChildItem "$src\browser" -File | Where-Object { $_.Extension -in '.json','.js','.html','.png' -or $_.Name -eq 'winup-firefox.xpi' }) { $args += "/resource:$($file.FullName),browser/$($file.Name)" }
foreach($name in 'file-engine.zip','file-engine.json','winfsp.msi') { $args += "/resource:$src\file-engine\$name,$name" }
foreach($file in Get-ChildItem "$src\licenses" -File) { $args += "/resource:$($file.FullName),licenses/$($file.Name)" }
foreach($name in 'WinUp.Passkeys.msix','WinUp.Passkeys.cer','package.json','Logo.png','setup.ps1','WinUp.PasskeyProvider.exe'){$args += "/resource:$src\system-passkeys\$name,system-passkeys/$name"}
$desktopLib=Join-Path $PSScriptRoot '..\dependencies\webview2\lib\net462'
$args += "/r:$desktopLib\Microsoft.Web.WebView2.Core.dll","/r:$desktopLib\Microsoft.Web.WebView2.WinForms.dll"
foreach($name in 'Microsoft.Web.WebView2.Core.dll','Microsoft.Web.WebView2.WinForms.dll'){$args += "/resource:$desktopLib\$name,desktop-deps/$name"}
$desktopNative=Join-Path $PSScriptRoot '..\dependencies\webview2\runtimes\win-x64\native\WebView2Loader.dll'
$args += "/resource:$desktopNative,desktop-deps/WebView2Loader.dll"
foreach($file in Get-ChildItem "$src\desktop" -File){$args += "/resource:$($file.FullName),desktop/$($file.Name)"}
$args += "/win32icon:$src\desktop\icon.ico"
$args += (Get-ChildItem $src -Filter '*.cs').FullName
$args += "$src\Properties\AssemblyInfo.cs"
if($ExtraSource){$args += [IO.Path]::GetFullPath($ExtraSource)}
if($EntryPoint){$args += "/main:$EntryPoint"}
& $csc @args
if($LASTEXITCODE) { throw 'WinUp build failed' }
Write-Output "Built: $Output"

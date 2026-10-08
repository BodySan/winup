param([string]$Output=(Join-Path $PSScriptRoot '..\WinUp.exe'),[string]$Source)
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
$args += (Get-ChildItem $src -Filter '*.cs').FullName
$args += "$src\Properties\AssemblyInfo.cs"
& $csc @args
if($LASTEXITCODE) { throw 'WinUp build failed' }
Write-Output "Built: $Output"

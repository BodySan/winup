$ErrorActionPreference='Stop'
$source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\src\browser'))
$manifest=Get-Content -LiteralPath (Join-Path $source 'firefox-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\firefox-submission'))
$stage=Join-Path $root ('source-'+$manifest.version)
New-Item -ItemType Directory -Force -Path $stage | Out-Null
$names=@($manifest.content_scripts|ForEach-Object {$_.js})+@($manifest.web_accessible_resources|ForEach-Object {$_.resources})+@('background.js','firefox-manifest.json','popup.html','popup.js','icon16.png','icon32.png','icon48.png','icon128.png')
foreach($name in $names|Select-Object -Unique){Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $stage $name) -Force}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\doc\EXTENSION-PRIVACY-RU.md') -Destination (Join-Path $stage 'PRIVACY.md') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\src\licenses\WinUp-GPL.txt') -Destination (Join-Path $stage 'LICENSE.txt') -Force
foreach($name in 'build.ps1','README.md'){Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('firefox-source\'+$name)) -Destination (Join-Path $stage $name) -Force}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$output=Join-Path $root ('winup-'+$manifest.version+'-source.zip')
if(Test-Path -LiteralPath $output){Remove-Item -LiteralPath $output}
$archive=[IO.Compression.ZipFile]::Open($output,[IO.Compression.ZipArchiveMode]::Create)
try{foreach($name in (@($names)+@('PRIVACY.md','LICENSE.txt','build.ps1','README.md')|Select-Object -Unique)){
 [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,(Join-Path $stage $name),$name)
}}finally{$archive.Dispose()}
Write-Output "Prepared source: $output"

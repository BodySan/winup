param([string]$Source,[string]$Output)
$ErrorActionPreference='Stop'
if(!$Source){$Source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\src\browser'))}
if(!$Output){$Output=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\firefox-submission'))}
$taskManifest=Get-Content -LiteralPath (Join-Path $Source 'firefox-manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($taskManifest.browser_specific_settings.gecko.id -ne 'winup@winup.local'){throw 'Unexpected extension ID'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
New-Item -ItemType Directory -Force $Output|Out-Null
$taskPath=Join-Path $Output ('winup-'+$taskManifest.version+'-unsigned.zip')
if(Test-Path -LiteralPath $taskPath){Remove-Item -LiteralPath $taskPath}
$taskNames=@($taskManifest.background.scripts)+@($taskManifest.content_scripts|ForEach-Object {$_.js})+@($taskManifest.web_accessible_resources|ForEach-Object {$_.resources})+@('popup.html','popup.js','icon16.png','icon32.png','icon48.png','icon128.png')
$taskArchive=[IO.Compression.ZipFile]::Open($taskPath,[IO.Compression.ZipArchiveMode]::Create)
try {
 foreach($taskName in $taskNames|Select-Object -Unique){
  if($taskName -notmatch '^[a-zA-Z0-9._-]+$'){throw 'Unexpected package path'}
  [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($taskArchive,(Join-Path $Source $taskName),$taskName)
 }
 $taskEntry=$taskArchive.CreateEntry('manifest.json');$taskWriter=[IO.StreamWriter]::new($taskEntry.Open(),[Text.UTF8Encoding]::new($false));try{$taskWriter.Write(($taskManifest|ConvertTo-Json -Depth 20))}finally{$taskWriter.Dispose()}
 [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($taskArchive,(Join-Path $PSScriptRoot '..\doc\EXTENSION-PRIVACY-RU.md'),'PRIVACY.md')
 [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($taskArchive,(Join-Path $PSScriptRoot '..\src\licenses\WinUp-GPL.txt'),'LICENSE.txt')
}finally{$taskArchive.Dispose()}
Write-Output "Prepared unsigned submission: $taskPath"
Write-Output 'This package requires Mozilla signing before permanent installation.'

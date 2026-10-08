param([string]$Output=(Join-Path $PSScriptRoot 'winup-unsigned.zip'))
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'firefox-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$worker='background-v'+$manifest.version+'.js'
$manifest.background.scripts=@($worker)
$names=@($manifest.background.scripts)+@($manifest.content_scripts|ForEach-Object {$_.js})+@($manifest.web_accessible_resources|ForEach-Object {$_.resources})+@('popup.html','popup.js','icon16.png','icon32.png','icon48.png','icon128.png','PRIVACY.md','LICENSE.txt')
if(Test-Path -LiteralPath $Output){Remove-Item -LiteralPath $Output}
$archive=[IO.Compression.ZipFile]::Open($Output,[IO.Compression.ZipArchiveMode]::Create)
try {
 foreach($name in $names|Select-Object -Unique){
  if($name -notmatch '^[a-zA-Z0-9._-]+$'){throw 'Unexpected package path'}
  $sourceName=if($name -eq $worker){'background.js'}else{$name}
  [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,(Join-Path $PSScriptRoot $sourceName),$name)
 }
 $entry=$archive.CreateEntry('manifest.json');$writer=[IO.StreamWriter]::new($entry.Open(),[Text.UTF8Encoding]::new($false))
 try{$writer.Write(($manifest|ConvertTo-Json -Depth 20))}finally{$writer.Dispose()}
}finally{$archive.Dispose()}
Write-Output "Built: $Output"

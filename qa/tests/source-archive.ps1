param([string]$Output='C:\WinUp\test\ci\source-check.zip')
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$taskOutput=[IO.Path]::GetFullPath($Output)
if(!$taskOutput.StartsWith('C:\WinUp\test\',[StringComparison]::OrdinalIgnoreCase)){throw 'Archive check output outside test workspace'}
New-Item -ItemType Directory -Force ([IO.Path]::GetDirectoryName($taskOutput))|Out-Null
& (Join-Path $taskRoot 'tools\archive-source.ps1') -Source (Join-Path $taskRoot 'src') -Output $taskOutput
Add-Type -AssemblyName System.IO.Compression.FileSystem
$taskArchive=[IO.Compression.ZipFile]::OpenRead($taskOutput)
try{
 foreach($taskName in @('src/build.ps1','src/Properties/AssemblyInfo.cs','doc/Инструкция.html','tools/verify-app.ps1')){
  if(!$taskArchive.GetEntry($taskName)){throw "Required source archive entry missing: $taskName"}
 }
 $taskGuide=[IO.StreamReader]::new($taskArchive.GetEntry('doc/Инструкция.html').Open())
 $taskHelp=[IO.StreamReader]::new($taskArchive.GetEntry('src/help.html').Open())
 try{if($taskGuide.ReadToEnd() -cne $taskHelp.ReadToEnd()){throw 'Archived manual differs from the application help.'}}
 finally{$taskGuide.Dispose();$taskHelp.Dispose()}
}finally{$taskArchive.Dispose()}
Write-Output 'PASS source archive built and required source, instruction and signature verifier present.'

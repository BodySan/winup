param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskSource=[IO.Path]::GetFullPath($Source)
Add-Type -AssemblyName System.IO.Compression
$taskItems=@()
foreach($taskTree in @(@{root=$taskSource;prefix='src'},@{root=(Join-Path $taskRoot 'tools');prefix='tools'},@{root=(Join-Path $taskRoot 'qa\security');prefix='qa/security'},@{root=(Join-Path $taskRoot 'qa\tests');prefix='qa/tests'},@{root=(Join-Path $taskRoot 'qa\fixtures');prefix='qa/fixtures'},@{root=(Join-Path $taskRoot 'doc\shots-1.15');prefix='doc/shots-1.15'},@{root=(Join-Path $taskRoot '.github');prefix='.github'})) {
 foreach($taskFile in Get-ChildItem -LiteralPath $taskTree.root -File -Recurse) {
  $taskRelative=$taskFile.FullName.Substring($taskTree.root.Length+1)
  if($taskRelative -match '(^|\\)(bin|obj|github)\\' -or $taskFile.Extension -in '.dpapi','.pfx','.p12','.kdbx','.keyx'){continue}
  $taskItems+=@{path=$taskFile.FullName;name=($taskTree.prefix+'/'+$taskRelative.Replace('\','/'))}
 }
}
foreach($taskName in 'README.md','LICENSE','.gitignore','.gitattributes') {$taskItems+=@{path=(Join-Path $taskRoot $taskName);name=$taskName}}
foreach($taskName in 'Инструкция.html','manual.src.html','manual-1.15.src.html','build-manual.ps1','file-section-1.16.html','password-organization-1.16.html','update-template-categories.ps1','DELIVERY-1.16.0.md','FILE-WORKFLOWS-1.16.md','UPDATES-SIMPLE-RU.md','DELIVERY-1.15.md','DELIVERY-1.15.1.md','DELIVERY-1.15.2.md','DELIVERY-1.15.3.md','EXTENSION-PRIVACY-RU.md','LOGIN-CORRECTIONS-1.15.1.md','LOGIN-ROUTES-2026-10-08.md','update-login-routes.ps1','QUESTIONS-AND-UX-2026-10-08.md','SECURITY-AUDIT-2026-10-08.md') {
 $taskPath=Join-Path (Join-Path $taskRoot 'doc') $taskName
 if(Test-Path -LiteralPath $taskPath){$taskItems+=@{path=$taskPath;name=('doc/'+$taskName)}}
}
$taskArchive=[IO.Compression.ZipArchive]::new([IO.File]::Create($Output),[IO.Compression.ZipArchiveMode]::Create)
try {
 foreach($taskItem in $taskItems) {
  $taskEntry=$taskArchive.CreateEntry($taskItem.name,[IO.Compression.CompressionLevel]::Optimal)
  $taskInput=[IO.File]::OpenRead($taskItem.path);$taskOutput=$taskEntry.Open()
  try {$taskInput.CopyTo($taskOutput)} finally {$taskInput.Dispose();$taskOutput.Dispose()}
 }
} finally {$taskArchive.Dispose()}
Write-Output ('Archived source and release tools: '+$taskItems.Count+' files')

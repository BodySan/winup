param([string]$Source,[string]$Go='go',[string]$Output)
$ErrorActionPreference='Stop'
if(!$Source){$Source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\src'))}
if(!$Output){$Output=Join-Path ([IO.Path]::GetDirectoryName($Source)) ('verify-packages-'+[Guid]::NewGuid().ToString('N'))}
if((& $Go version) -ne 'go version go1.27.2 windows/amd64'){throw 'Reproducibility check requires Go 1.27.2 for Windows amd64'}
New-Item -ItemType Directory -Force -Path $Output|Out-Null
$taskOld=Get-Location
$taskBuildEnvironment=@{CGO_ENABLED='0';GOOS='windows';GOARCH='amd64';GOAMD64='v1';GOTOOLCHAIN='local';GOWORK='off'}
$taskOldEnvironment=@{}
foreach($taskName in $taskBuildEnvironment.Keys){$taskOldEnvironment[$taskName]=[Environment]::GetEnvironmentVariable($taskName);[Environment]::SetEnvironmentVariable($taskName,$taskBuildEnvironment[$taskName])}
try{
 Set-Location -LiteralPath (Join-Path $Source 'vendor\file-packages')
 & $Go build -mod=vendor -trimpath -buildvcs=false -ldflags '-s -w' -o (Join-Path $Output 'WinUpPackages.exe') .
 if($LASTEXITCODE){throw 'Independent package helper rebuild failed'}
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $taskZip=[IO.Compression.ZipFile]::OpenRead((Join-Path $Source 'file-engine\file-engine.zip'))
 try{
  $taskEntry=$taskZip.GetEntry('WinUpPackages.exe');if(!$taskEntry){throw 'Package helper absent from shipped runtime'}
  $taskInput=$taskEntry.Open();$taskHash=[Security.Cryptography.SHA256]::Create()
  try{$taskExpected=[BitConverter]::ToString($taskHash.ComputeHash($taskInput)).Replace('-','')}finally{$taskInput.Dispose();$taskHash.Dispose()}
 }finally{$taskZip.Dispose()}
 $taskActual=(Get-FileHash -LiteralPath (Join-Path $Output 'WinUpPackages.exe')).Hash
 if($taskExpected -ne $taskActual){throw 'Shipped package helper differs from the rebuild of published sources'}
 [IO.File]::WriteAllText((Join-Path $Output 'reproducibility.txt'),('PASS package helper rebuilt identically from vendored source; Go 1.27.2; SHA256='+$taskActual),[Text.UTF8Encoding]::new($false))
 Write-Output ('PASS package helper rebuilt identically; SHA256='+$taskActual)
}finally{Set-Location $taskOld;foreach($taskName in $taskOldEnvironment.Keys){[Environment]::SetEnvironmentVariable($taskName,$taskOldEnvironment[$taskName])}}

param([string]$Go='go')
$ErrorActionPreference='Stop'
$taskSource=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$taskHelper=Join-Path $PSScriptRoot ('WinUpPackages-'+[Guid]::NewGuid().ToString('N')+'.exe')
$taskOldLocation=Get-Location
try {
    Set-Location -LiteralPath $PSScriptRoot
    & $Go build -mod=vendor -trimpath -ldflags '-s -w' -o $taskHelper .
    if($LASTEXITCODE){throw 'File package helper build failed'}
    Add-Type -AssemblyName System.IO.Compression
    $taskFile=[IO.File]::Open((Join-Path $taskSource 'file-engine\file-engine.zip'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
    $taskZip=[IO.Compression.ZipArchive]::new($taskFile,[IO.Compression.ZipArchiveMode]::Update)
    try {
        $taskPrevious=$taskZip.GetEntry('WinUpPackages.exe');if($taskPrevious){$taskPrevious.Delete()}
        $taskEntry=$taskZip.CreateEntry('WinUpPackages.exe',[IO.Compression.CompressionLevel]::Optimal)
        $taskInput=[IO.File]::OpenRead($taskHelper);$taskOutput=$taskEntry.Open()
        try{$taskInput.CopyTo($taskOutput)}finally{$taskInput.Dispose();$taskOutput.Dispose()}
    } finally {$taskZip.Dispose();$taskFile.Dispose()}
    $taskHashes=Get-Content -LiteralPath (Join-Path $taskSource 'file-engine\file-engine.json') -Raw | ConvertFrom-Json
    $taskHashes | Add-Member -NotePropertyName 'WinUpPackages.exe' -NotePropertyValue ((Get-FileHash -LiteralPath $taskHelper).Hash.ToLowerInvariant()) -Force
    [IO.File]::WriteAllText((Join-Path $taskSource 'file-engine\file-engine.json'),($taskHashes|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    Write-Output 'Built offline from vendored sources; embedded WinUpPackages.exe and updated its SHA-256.'
} finally {Set-Location $taskOldLocation;if(Test-Path -LiteralPath $taskHelper){Remove-Item -LiteralPath $taskHelper}}

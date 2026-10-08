param([Parameter(Mandatory=$true)][string]$Jdk24)
$ErrorActionPreference='Stop'
$src=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$javac=Join-Path $Jdk24 'bin\javac.exe'
if(!(Test-Path $javac)) { throw 'Provide the path to a JDK 24 installation.' }
$runtime=Join-Path ([IO.Path]::GetTempPath()) ('WinUp-files-build-'+[Guid]::NewGuid().ToString('N'))
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory("$src\file-engine\file-engine.zip",$runtime)
& "$PSScriptRoot\patch-jfuse.ps1" -Runtime $runtime -Compiler $javac
$classpath=(@((Get-ChildItem "$runtime\app\mods" -Filter '*.jar').FullName)+@((Get-ChildItem "$runtime\app" -Filter '*.jar').FullName)) -join ';'
& $javac --release 24 -encoding UTF-8 -cp $classpath -d "$runtime\app\winup-files" "$PSScriptRoot\WinUpFiles.java"
if($LASTEXITCODE) { throw "Java adapter build failed; build directory: $runtime" }
$stream=[IO.File]::Create("$src\file-engine\file-engine.zip")
$zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
$hashes=[ordered]@{}
try {
    foreach($file in Get-ChildItem $runtime -Recurse -File) {
        $relative=$file.FullName.Substring($runtime.Length+1).Replace('\','/')
        $hashes[$relative]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $entry=$zip.CreateEntry($relative); $output=$entry.Open(); $input=[IO.File]::OpenRead($file.FullName)
        try { $input.CopyTo($output) } finally { $input.Dispose(); $output.Dispose() }
    }
} finally { $zip.Dispose(); $stream.Dispose() }
$hashes | ConvertTo-Json | Set-Content "$src\file-engine\file-engine.json"
Write-Output "Built engine. Temporary build directory: $runtime"

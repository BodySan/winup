$ErrorActionPreference='Stop'
$work=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$runtime=Join-Path $work 'vendor\cryptomator-cli\cryptomator-cli'
$classpath=(@((Get-ChildItem "$runtime\app\mods" -Filter '*.jar').FullName)+@((Get-ChildItem "$runtime\app" -Filter '*.jar').FullName)) -join ';'
& "$runtime\WinUpCompiler.exe" -24 -encoding UTF-8 -cp $classpath -d "$runtime\app\winup-files" "$work\src\vendor\file-engine\WinUpFiles.java"
if($LASTEXITCODE) { throw 'Java adapter build failed' }
Add-Type -AssemblyName System.IO.Compression
$stream=[IO.File]::Create("$work\src\file-engine\file-engine.zip")
$zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
$hashes=[ordered]@{}
try {
    foreach($file in Get-ChildItem $runtime -Recurse -File | Where-Object { $_.Name -notin 'cryptomator-cli.exe','WinUpCompiler.exe','ecj.jar','cryptomator-cli.cfg','WinUpCompiler.cfg' }) {
        $relative=$file.FullName.Substring($runtime.Length+1).Replace('\','/')
        $hashes[$relative]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $entry=$zip.CreateEntry($relative)
        $output=$entry.Open(); $input=[IO.File]::OpenRead($file.FullName)
        try { $input.CopyTo($output) } finally { $input.Dispose(); $output.Dispose() }
    }
} finally { $zip.Dispose(); $stream.Dispose() }
$hashes | ConvertTo-Json | Set-Content "$work\src\file-engine\file-engine.json"

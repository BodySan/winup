param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$destination=[IO.Path]::GetFullPath($Output)
if(Test-Path -LiteralPath $destination) { throw 'Use a new, empty candidate directory.' }
New-Item -ItemType Directory $destination | Out-Null
foreach($file in Get-ChildItem -LiteralPath $source -Recurse -File) {
    $relative=$file.FullName.Substring($source.Length+1)
    if($relative -match '^(bin|obj)\\') { continue }
    $target=Join-Path $destination $relative
    New-Item -ItemType Directory -Force ([IO.Path]::GetDirectoryName($target)) | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $target
}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
$versions=Get-Content "$destination\updates\versions.json" -Raw | ConvertFrom-Json
$report=@()
$specs=@(
    @{id='bouncycastle';package='bouncycastle.cryptography';dll='BouncyCastle.Cryptography.dll';framework='net461'},
    @{id='cbor';package='petero.cbor';dll='CBOR.dll';framework='net40'},
    @{id='numbers';package='petero.numbers';dll='Numbers.dll';framework='net40'}
)
foreach($spec in $specs) {
    $base="https://api.nuget.org/v3-flatcontainer/$($spec.package)"
    $index=Invoke-RestMethod "$base/index.json"
    $latest=@($index.versions | Where-Object { $_ -match '^\d+\.\d+\.\d+(\.\d+)?$' } | Sort-Object { [version]$_ })[-1]
    $installed=[string]$versions.($spec.id)
    if(([version]$latest).Major -ne ([version]$installed).Major) { $report+=@{id=$spec.id;installed=$installed;latest=$latest;status='New major requires adapter review'}; continue }
    if([version]$latest -le [version]$installed) { $report+=@{id=$spec.id;installed=$installed;latest=$latest;status='Current'}; continue }
    $package=Join-Path $destination "$($spec.id).nupkg"
    Invoke-WebRequest "$base/$latest/$($spec.package).$latest.nupkg" -OutFile $package -UseBasicParsing
    & dotnet nuget verify $package --all
    if($LASTEXITCODE) { throw "NuGet signature verification failed: $($spec.package)" }
    $zip=[IO.Compression.ZipFile]::OpenRead($package)
    try {
        $entry=$zip.GetEntry("lib/$($spec.framework)/$($spec.dll)")
        if(!$entry) { throw "Supported framework removed in $($spec.package); adapter review required." }
        $input=$entry.Open(); $outputStream=[IO.File]::Create("$destination\lib\$($spec.dll)")
        try { $input.CopyTo($outputStream) } finally { $input.Dispose(); $outputStream.Dispose() }
    } finally { $zip.Dispose() }
    Remove-Item -LiteralPath $package
    $versions.($spec.id)=$latest
    $report+=@{id=$spec.id;installed=$installed;latest=$latest;status='Candidate; tests required'}
}
$psl=Invoke-WebRequest https://publicsuffix.org/list/public_suffix_list.dat -UseBasicParsing
if($psl.Content.Length -lt 100000 -or $psl.Content.Length -gt 2097152 -or $psl.Content -notmatch '(?m)^// VERSION: ') { throw 'Invalid official PSL response.' }
[IO.File]::WriteAllText("$destination\public-suffix-list.dat",$psl.Content,[Text.UTF8Encoding]::new($false))
foreach($artifact in 'cryptofs','cryptolib') {
    [xml]$metadata=(Invoke-WebRequest "https://repo.maven.apache.org/maven2/org/cryptomator/$artifact/maven-metadata.xml" -UseBasicParsing).Content
    $report+=@{id=$artifact;installed=[string]$versions.$artifact;latest=[string]$metadata.metadata.versioning.release;status='Pinned to verified Cryptomator runtime; separate rebuild required'}
}
$notes=[IO.File]::ReadAllText("$destination\THIRD-PARTY.md")
$notes+="`n## Версии кандидата обновления`n`n"
foreach($spec in $specs) { $notes+="$($spec.package): $($versions.($spec.id)). Оригинальная DLL из подписанного NuGet-пакета, лицензия сохранена.`n`n" }
[IO.File]::WriteAllText("$destination\THIRD-PARTY.md",$notes,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText("$destination\updates\versions.json",($versions | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText("$destination\updates\candidate-report.json",($report | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
& "$destination\vendor\passkeys\build.ps1"
& "$destination\updates\prepare.ps1"
Write-Output "Candidate prepared; NOT signed or published: $destination"

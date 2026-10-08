param([Parameter(Mandatory=$true)][string]$Candidate)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$trusted=Join-Path $root 'src'
$candidatePath=[IO.Path]::GetFullPath($Candidate)
$mutable=@('lib\BouncyCastle.Cryptography.dll','lib\CBOR.dll','lib\Numbers.dll','lib\WinUp.PasskeyEngine.dll','public-suffix-list.dat','THIRD-PARTY.md','updates\versions.json','updates\components.json','updates\candidate-report.json')
foreach($file in Get-ChildItem -LiteralPath $candidatePath -Recurse -File) {
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Candidate contains filesystem links.' }
    $relative=$file.FullName.Substring($candidatePath.Length+1)
    if($relative -in $mutable) { continue }
    $original=Join-Path $trusted $relative
    if(!(Test-Path -LiteralPath $original)) { throw "Candidate altered locally trusted code/resource: $relative" }
    $candidateHash=(Get-FileHash -LiteralPath $file.FullName).Hash
    $originalHash=(Get-FileHash -LiteralPath $original).Hash
    if($candidateHash -ne $originalHash -and $relative -in 'browser\manifest.json','browser\firefox-manifest.json') {
        # prepare.ps1 writes these two manifests with ConvertTo-Json. Reproduce
        # that formatting from the locally trusted manifest, including every
        # field. The candidate must still match the resulting bytes exactly.
        $manifest=Get-Content -LiteralPath $original -Raw -Encoding UTF8 | ConvertFrom-Json
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $originalHash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 12)))).Replace('-','') }
        finally { $sha.Dispose() }
    }
    if($candidateHash -ne $originalHash) { throw "Candidate altered locally trusted code/resource: $relative" }
}
foreach($file in Get-ChildItem -LiteralPath $trusted -Recurse -File) {
    $relative=$file.FullName.Substring($trusted.Length+1)
    if($relative -match '^(bin|obj)\\') { continue }
    if(!(Test-Path -LiteralPath (Join-Path $candidatePath $relative))) { throw "Candidate omitted trusted file: $relative" }
}
$baseline=Get-Content "$trusted\updates\versions.json" -Raw | ConvertFrom-Json
$versions=Get-Content "$candidatePath\updates\versions.json" -Raw | ConvertFrom-Json
$specs=@(
    @{id='bouncycastle';package='bouncycastle.cryptography';dll='BouncyCastle.Cryptography.dll';framework='net461'},
    @{id='cbor';package='petero.cbor';dll='CBOR.dll';framework='net40'},
    @{id='numbers';package='petero.numbers';dll='Numbers.dll';framework='net40'}
)
if((($versions.PSObject.Properties.Name | Sort-Object) -join ',') -ne (($baseline.PSObject.Properties.Name | Sort-Object) -join ',')) { throw 'Unexpected candidate version fields.' }
foreach($property in $baseline.PSObject.Properties) {
    if($property.Name -notin $specs.id -and $versions.($property.Name) -ne $property.Value) { throw 'Candidate changed a pinned runtime version.' }
}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
$checks=Join-Path ([IO.Path]::GetDirectoryName($candidatePath)) 'upstream-verification'
New-Item -ItemType Directory -Force $checks | Out-Null
foreach($spec in $specs) {
    $version=[string]$versions.($spec.id)
    if($version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$' -or ([version]$version).Major -ne ([version]$baseline.($spec.id)).Major -or [version]$version -lt [version]$baseline.($spec.id)) { throw 'Unsupported candidate dependency version.' }
    $package=Join-Path $checks "$($spec.id).nupkg"
    Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/$($spec.package)/$version/$($spec.package).$version.nupkg" -OutFile $package -UseBasicParsing
    & dotnet nuget verify $package --all
    if($LASTEXITCODE) { throw 'Official NuGet signature verification failed.' }
    $zip=[IO.Compression.ZipFile]::OpenRead($package)
    try {
        $entry=$zip.GetEntry("lib/$($spec.framework)/$($spec.dll)"); if(!$entry) { throw 'Supported framework absent.' }
        $input=$entry.Open(); $sha=[Security.Cryptography.SHA256]::Create()
        try { $expected=[BitConverter]::ToString($sha.ComputeHash($input)).Replace('-','') } finally { $input.Dispose(); $sha.Dispose() }
        if((Get-FileHash -LiteralPath "$candidatePath\lib\$($spec.dll)").Hash -ne $expected) { throw 'Candidate DLL differs from the official signed NuGet package.' }
    } finally { $zip.Dispose() }
}
& "$PSScriptRoot\verify-psl.ps1" -Candidate "$candidatePath\public-suffix-list.dat" -Trusted "$trusted\public-suffix-list.dat" -Output (Join-Path $checks 'psl-immutable.dat')
$adapterHash=(Get-FileHash -LiteralPath "$candidatePath\lib\WinUp.PasskeyEngine.dll").Hash
# This script was compared with the local trusted source above. Rebuild with verified dependencies.
& "$candidatePath\vendor\passkeys\build.ps1"
if((Get-FileHash -LiteralPath "$candidatePath\lib\WinUp.PasskeyEngine.dll").Hash -ne $adapterHash) { throw 'Passkey adapter is not reproducible from trusted source and official dependencies.' }
$notes=[IO.File]::ReadAllText("$trusted\THIRD-PARTY.md")+"`n## Версии кандидата обновления`n`n"
foreach($spec in $specs) { $notes+="$($spec.package): $($versions.($spec.id)). Оригинальная DLL из подписанного NuGet-пакета, лицензия сохранена.`n`n" }
[IO.File]::WriteAllText("$candidatePath\THIRD-PARTY.md",$notes,[Text.UTF8Encoding]::new($false))
Write-Output 'Candidate code matches locally trusted source; dependencies match signed upstream packages; adapter rebuilt identically.'

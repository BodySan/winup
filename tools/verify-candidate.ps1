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
    if(!(Test-Path -LiteralPath $original) -or (Get-FileHash -LiteralPath $file.FullName).Hash -ne (Get-FileHash -LiteralPath $original).Hash) { throw "Candidate altered locally trusted code/resource: $relative" }
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
$pslCheck=Join-Path $checks 'public-suffix-list.dat'
Invoke-WebRequest ('https://publicsuffix.org/list/public_suffix_list.dat?winup='+[Guid]::NewGuid().ToString('N')) -Headers @{'Cache-Control'='no-cache'} -OutFile $pslCheck -UseBasicParsing
$candidatePsl=(Get-FileHash -LiteralPath "$candidatePath\public-suffix-list.dat").Hash
$trustedPsl=(Get-FileHash -LiteralPath "$trusted\public-suffix-list.dat").Hash
if($candidatePsl -ne $trustedPsl) {
    $stamp=[regex]::Match([IO.File]::ReadAllText("$candidatePath\public-suffix-list.dat"),'(?m)^// VERSION: (\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_UTC)').Groups[1].Value
    $bundledStamp=[regex]::Match([IO.File]::ReadAllText("$trusted\public-suffix-list.dat"),'(?m)^// VERSION: (\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_UTC)').Groups[1].Value
    if(!$stamp -or !$bundledStamp -or [string]::CompareOrdinal($stamp,$bundledStamp) -lt 0 -or $candidatePsl -ne (Get-FileHash -LiteralPath $pslCheck).Hash) { throw 'Candidate PSL is older than the trusted baseline or differs from current official bytes. Run new component checks.' }
} else { Write-Output 'PSL matches the already trusted bundled snapshot; no downgrade from stale CDN data.' }
$adapterHash=(Get-FileHash -LiteralPath "$candidatePath\lib\WinUp.PasskeyEngine.dll").Hash
# This script was compared with the local trusted source above. Rebuild with verified dependencies.
& "$candidatePath\vendor\passkeys\build.ps1"
if((Get-FileHash -LiteralPath "$candidatePath\lib\WinUp.PasskeyEngine.dll").Hash -ne $adapterHash) { throw 'Passkey adapter is not reproducible from trusted source and official dependencies.' }
$notes=[IO.File]::ReadAllText("$trusted\THIRD-PARTY.md")+"`n## Версии кандидата обновления`n`n"
foreach($spec in $specs) { $notes+="$($spec.package): $($versions.($spec.id)). Оригинальная DLL из подписанного NuGet-пакета, лицензия сохранена.`n`n" }
[IO.File]::WriteAllText("$candidatePath\THIRD-PARTY.md",$notes,[Text.UTF8Encoding]::new($false))
Write-Output 'Candidate code matches locally trusted source; dependencies match signed upstream packages; adapter rebuilt identically.'

param([Parameter(Mandatory=$true)][long]$Sequence,[Parameter(Mandatory=$true)][string]$Output,
      [string]$ProtectedKey,[string]$Source)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
if(!$ProtectedKey) { $ProtectedKey=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\.release-private\component-signing.dpapi')) }
if($Sequence -lt 1 -or $Sequence -gt [int]::MaxValue) { throw 'Sequence must be 1..2147483647 and increase for each release.' }
$src=if($Source) { [IO.Path]::GetFullPath($Source) } else { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')) }
& "$PSScriptRoot\prepare.ps1" -Source $src
$manifest=Get-Content "$src\updates\components.json" -Raw | ConvertFrom-Json
$manifest.sequence=$Sequence
$rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(); $rsa.PersistKeyInCsp=$false
$privateBytes=$null
try {
    if($env:WINUP_COMPONENT_SIGNING_XML) { $rsa.FromXmlString($env:WINUP_COMPONENT_SIGNING_XML) }
    else {
        $privateBytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($ProtectedKey),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        $rsa.FromXmlString([Text.Encoding]::UTF8.GetString($privateBytes))
    }
    if($rsa.KeySize -lt 3072 -or $rsa.ToXmlString($false) -ne [IO.File]::ReadAllText("$PSScriptRoot\publisher.xml")) { throw 'Signing key does not match the public key in WinUp.' }
    New-Item -ItemType Directory -Force $Output | Out-Null
    Add-Type -AssemblyName System.IO.Compression
    $raw=[Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 8))
    $signature=$rsa.SignData($raw,'SHA256')
    $package=Join-Path $Output 'components.wup'
    $stream=[IO.File]::Create($package); $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach($meta in @{ 'manifest.json'=$raw; 'manifest.sig'=$signature }.GetEnumerator()) {
            $outputStream=$zip.CreateEntry($meta.Key).Open(); try { $outputStream.Write($meta.Value,0,$meta.Value.Length) } finally { $outputStream.Dispose() }
        }
        foreach($property in $manifest.files.PSObject.Properties) {
            $name=$property.Name
            $path=if($name -in 'file-engine.zip','file-engine.json','winfsp.msi') { "$src\file-engine\$name" }
                elseif($name.EndsWith('.dll')) { "$src\lib\$name" } else { Join-Path $src $name }
            $entry=$zip.CreateEntry($name,[IO.Compression.CompressionLevel]::Optimal)
            $input=[IO.File]::OpenRead($path); $outputStream=$entry.Open()
            try { $input.CopyTo($outputStream) } finally { $input.Dispose(); $outputStream.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
    $release=@{schema=1;sequence=$Sequence;package='components.wup';size=(Get-Item $package).Length;
        sha256=(Get-FileHash -LiteralPath $package).Hash.ToLowerInvariant();expiresUtc=[DateTimeOffset]::UtcNow.AddDays(28).ToString('o')}
    $feed=[Text.Encoding]::UTF8.GetBytes(($release | ConvertTo-Json))
    [IO.File]::WriteAllBytes((Join-Path $Output 'update.json'),$feed)
    [IO.File]::WriteAllBytes((Join-Path $Output 'update.sig'),$rsa.SignData($feed,'SHA256'))
    Write-Output "Signed component release ${Sequence}: $package"
} finally { if($privateBytes) { [Array]::Clear($privateBytes,0,$privateBytes.Length) }; $rsa.Dispose() }

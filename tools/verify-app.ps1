param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
$application=[IO.Path]::GetFullPath($Path)
if((Get-Item -LiteralPath $application).Length -gt 256MB -or (Get-Item -LiteralPath ($application+'.sig')).Length -gt 1024) { throw 'Invalid application/signature size.' }
$trusted=Join-Path $PSScriptRoot '..\src\updates\publisher.xml'
$rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(); $rsa.PersistKeyInCsp=$false
try {
    $rsa.FromXmlString([IO.File]::ReadAllText($trusted))
    if($rsa.KeySize -lt 3072 -or !$rsa.VerifyData([IO.File]::ReadAllBytes($application),'SHA256',[IO.File]::ReadAllBytes($application+'.sig'))) { throw 'Application signature is INVALID. Do not start or replace WinUp with this file.' }
    Write-Output 'PASS application signature matches the locally trusted WinUp publisher key.'
} finally { $rsa.Dispose() }

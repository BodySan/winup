param([Parameter(Mandatory=$true)][string]$SdkBin,[string]$Source,[string]$Thumbprint,[string]$Output)
$ErrorActionPreference='Stop'
if(!$Source){$Source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\src'))}
if(!$Output){$Output=Join-Path $Source 'system-passkeys'}
New-Item -ItemType Directory -Force $Output|Out-Null
foreach($tool in 'makeappx.exe','signtool.exe'){$sig=Get-AuthenticodeSignature -LiteralPath (Join-Path $SdkBin $tool);if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation,'){throw 'Windows SDK tool signature is not valid.'}}
if(!$Thumbprint){throw 'Provide the local Windows code-signing certificate thumbprint.'}
$cert=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$Thumbprint)
if($cert.Subject -ne 'CN=WinUp' -or !$cert.HasPrivateKey){throw 'Wrong code-signing certificate.'}
$stage=Join-Path $Output ('build-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage|Out-Null
Copy-Item -LiteralPath (Join-Path $Source 'system-passkeys\Package.appxmanifest') -Destination (Join-Path $stage 'AppxManifest.xml')
& (Join-Path $SdkBin 'makeappx.exe') pack /o /d $stage /nv /p (Join-Path $Output 'WinUp.Passkeys.msix')
if($LASTEXITCODE){throw 'Identity package build failed.'}
& (Join-Path $SdkBin 'signtool.exe') sign /fd SHA256 /s My /sha1 $Thumbprint (Join-Path $Output 'WinUp.Passkeys.msix')
if($LASTEXITCODE){throw 'Identity package signing failed.'}
Export-Certificate -Cert $cert -FilePath (Join-Path $Output 'WinUp.Passkeys.cer')|Out-Null
Copy-Item -LiteralPath (Join-Path $Source 'browser\icon128.png') -Destination (Join-Path $Output 'Logo.png')
$manifest=[ordered]@{schema=1;thumbprint=$cert.Thumbprint;packageHash=(Get-FileHash -LiteralPath (Join-Path $Output 'WinUp.Passkeys.msix')).Hash.ToLowerInvariant()}
[IO.File]::WriteAllText((Join-Path $Output 'package.json'),($manifest|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
# Preserve the build directory for package diagnostics; it contains only the public manifest.

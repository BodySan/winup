param([string]$Source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')))
$ErrorActionPreference='Stop'
$Source=[IO.Path]::GetFullPath($Source)
foreach($name in 'Numbers','CBOR','BouncyCastle.Cryptography','WinUp.PasskeyEngine'){[Reflection.Assembly]::LoadFrom((Join-Path $Source ('lib\'+$name+'.dll')))|Out-Null}
[IO.File]::WriteAllBytes((Join-Path $Source 'system-passkeys\authenticator-info.cbor'),[WinUp.PasskeyEngine.Keys]::SystemAuthenticatorInfo())
$csc="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $csc /nologo /target:winexe /platform:anycpu /unsafe+ /langversion:5 /define:PASSKEY_PROVIDER /main:WinUp.ProviderProgram "/win32manifest:$Source\system-passkeys\Provider.manifest" "/out:$Source\system-passkeys\WinUp.PasskeyProvider.exe" /r:System.Windows.Forms.dll /r:System.Web.Extensions.dll /r:System.Security.dll "/resource:$Source\system-passkeys\authenticator-info.cbor,authenticator-info.cbor" "$Source\SystemPasskeyProvider.cs" "$Source\SystemPasskeyNative.cs" "$Source\SystemPasskeyCache.cs" "$Source\system-passkeys\ProviderEnvironment.cs"
if($LASTEXITCODE){throw 'System passkey provider build failed.'}

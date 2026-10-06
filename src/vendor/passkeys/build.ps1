$ErrorActionPreference='Stop'
$src=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$sdk=Get-Item 'C:\Program Files\dotnet\sdk\8.0.425' -ErrorAction SilentlyContinue
if(!$sdk) { throw 'Install .NET SDK 8.0.425 to reproducibly rebuild the passkey adapter.' }
$framework="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319"
$compiler=Join-Path $sdk.FullName 'Roslyn\bincore\csc.dll'
$arguments=@('/nologo','/target:library','/langversion:latest','/deterministic+',"/out:$src\lib\WinUp.PasskeyEngine.dll",
    "/r:$framework\mscorlib.dll","/r:$framework\System.dll","/r:$framework\System.Core.dll")
foreach($library in 'BouncyCastle.Cryptography','CBOR','Numbers') { $arguments += "/r:$src\lib\$library.dll" }
$arguments += (Get-ChildItem $PSScriptRoot -Filter '*.cs').FullName
& dotnet $compiler @arguments
if($LASTEXITCODE) { throw 'Passkey adapter build failed.' }

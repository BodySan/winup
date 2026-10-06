$ErrorActionPreference='Stop'
$src=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$sdk=Get-ChildItem 'C:\Program Files\dotnet\sdk' -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'Roslyn\bincore\csc.dll') } | Sort-Object { [version]($_.Name.Split('-')[0]) } -Descending | Select-Object -First 1
if(!$sdk) { throw 'Install a .NET SDK with Roslyn to rebuild the passkey adapter.' }
$framework="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319"
$compiler=Join-Path $sdk.FullName 'Roslyn\bincore\csc.dll'
$arguments=@('/nologo','/target:library','/langversion:latest',"/out:$src\lib\WinUp.PasskeyEngine.dll",
    "/r:$framework\mscorlib.dll","/r:$framework\System.dll","/r:$framework\System.Core.dll")
foreach($library in 'BouncyCastle.Cryptography','CBOR','Numbers') { $arguments += "/r:$src\lib\$library.dll" }
$arguments += (Get-ChildItem $PSScriptRoot -Filter '*.cs').FullName
& dotnet $compiler @arguments
if($LASTEXITCODE) { throw 'Passkey adapter build failed.' }

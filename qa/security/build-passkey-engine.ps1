$ErrorActionPreference='Stop'
$src=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\src'))
$sdk=Get-ChildItem 'C:\Program Files\dotnet\sdk' -Directory | Sort-Object Name -Descending | Select-Object -First 1
$csc=Join-Path $sdk.FullName 'Roslyn\bincore\csc.dll'
$framework="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319"
$args=@('/nologo','/target:library','/langversion:latest',"/out:$src\lib\WinUp.PasskeyEngine.dll",
    "/r:$framework\mscorlib.dll","/r:$framework\System.dll","/r:$framework\System.Core.dll")
foreach($library in 'BouncyCastle.Cryptography','CBOR','Numbers') { $args += "/r:$src\lib\$library.dll" }
$args += (Get-ChildItem "$src\vendor\passkeys" -Filter '*.cs').FullName
& dotnet $csc @args
if($LASTEXITCODE) { throw 'Passkey engine build failed' }

param([Parameter(Mandatory=$true)][string]$Runtime,[Parameter(Mandatory=$true)][string]$Compiler,[switch]$Ecj)
$ErrorActionPreference='Stop'
$classpath=(@((Get-ChildItem "$Runtime\app\mods" -Filter '*.jar').FullName)+@((Get-ChildItem "$Runtime\app" -Filter '*.jar').FullName)) -join ';'
$classes=Join-Path ([IO.Path]::GetTempPath()) ('WinUp-jfuse-patch-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $classes | Out-Null
$arguments=@();if($Ecj){$arguments+= '-24'}else{$arguments+= '--release','24'}
& $Compiler @arguments -encoding UTF-8 -cp $classpath -d $classes "$PSScriptRoot\jfuse-win\FuseMountImpl.java"
if($LASTEXITCODE){throw 'WinFsp lifecycle patch compilation failed'}
Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem
$jar=[IO.Compression.ZipFile]::Open("$Runtime\app\mods\jfuse-win-0.7.3.jar",[IO.Compression.ZipArchiveMode]::Update)
try {
    $name='org/cryptomator/jfuse/win/FuseMountImpl.class'
    $entry=$jar.GetEntry($name);if(!$entry){throw 'Unexpected jfuse-win archive'};$entry.Delete()
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($jar,(Join-Path $classes $name),$name)|Out-Null
}finally{$jar.Dispose()}
Write-Output 'Built documented jfuse WinFsp lifecycle patch.'

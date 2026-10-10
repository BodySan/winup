param([string]$Source=(Join-Path $PSScriptRoot '..\..\src'),[string]$Executable)
$ErrorActionPreference='Stop'
$Source=[IO.Path]::GetFullPath($Source)
$attributes=[IO.File]::ReadAllText((Join-Path $Source 'Properties\AssemblyInfo.cs'))
$version=[regex]::Match($attributes,'AssemblyVersion\("([0-9.]+)"\)').Groups[1].Value
$fileVersion=[regex]::Match($attributes,'AssemblyFileVersion\("([0-9.]+)"\)').Groups[1].Value
$display=[regex]::Match($attributes,'AssemblyInformationalVersion\("([0-9.]+)"\)').Groups[1].Value
if(!$version -or $fileVersion -ne $version -or !$display){throw 'Application version attributes disagree.'}
$numeric=[Version]$version
$parts=@($display.Split('.'))
if($parts.Count -gt 4){throw 'Product version has too many parts.'}
while($parts.Count -lt 4){$parts+='0'}
$normalizedDisplay=([Version]($parts -join '.')).ToString()
if($normalizedDisplay -ne $numeric.ToString()){throw 'Product and application versions disagree.'}
$project=[xml][IO.File]::ReadAllText((Join-Path $Source 'WinUp.csproj'))
if($project.Project.PropertyGroup.Version -ne $version){throw 'Project version disagrees with assembly version.'}
$package=[xml][IO.File]::ReadAllText((Join-Path $Source 'system-passkeys\Package.appxmanifest'))
if($package.Package.Identity.Version -ne $version){throw 'Windows package version disagrees with application version.'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::OpenRead((Join-Path $Source 'system-passkeys\WinUp.Passkeys.msix'))
try{
 $reader=[IO.StreamReader]::new($zip.GetEntry('AppxManifest.xml').Open())
 try{$packed=[xml]$reader.ReadToEnd()}finally{$reader.Dispose()}
 if($packed.Package.Identity.Version -ne $version){throw 'Compiled Windows package has a different version.'}
}finally{$zip.Dispose()}
$provider=(Get-Item -LiteralPath (Join-Path $Source 'system-passkeys\WinUp.PasskeyProvider.exe')).VersionInfo
if($provider.FileVersion -ne $version -or $provider.ProductVersion -ne $display){throw 'Compiled provider has a different version.'}
$components=Get-Content -LiteralPath (Join-Path $Source 'updates\components.json') -Raw|ConvertFrom-Json
if($components.minApp -ne $version -or $components.maxApp -ne "$($numeric.Major).$($numeric.Minor).999.999"){throw 'Component compatibility range disagrees with application version.'}
$manual=[IO.File]::ReadAllText((Join-Path $Source 'help.html'))
if(!$manual.Contains('<title>WinUp '+$display+' — инструкция</title>')){throw 'Manual version disagrees with application version.'}
if($Executable){
 $built=(Get-Item -LiteralPath $Executable).VersionInfo
 if($built.FileVersion -ne $version -or $built.ProductVersion -ne $display){throw 'Built application has a different version.'}
 if([Reflection.AssemblyName]::GetAssemblyName([IO.Path]::GetFullPath($Executable)).Version.ToString() -ne $version){throw 'Built assembly has a different version.'}
}
Write-Output ('PASS release version '+$display+'; assembly, project, Windows package, provider, manual and component compatibility agree.')

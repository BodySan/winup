param([string]$Output = 'C:\WinUp\test\audit\candidate',[string]$Source,[switch]$HostNativeReview,[switch]$HostNativeReviewOnly,[switch]$SystemProviderOnly,[switch]$SecurityReviewOnly,[switch]$PackageSecurityOnly,[switch]$FollowupSecurityOnly,[switch]$FileWorkflowsOnly,[switch]$CsvExportOnly)
$ErrorActionPreference = 'Stop'
$src = if($Source) { [IO.Path]::GetFullPath($Source) } else { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\src')) }
New-Item -ItemType Directory -Force $Output | Out-Null
& "$src\updates\prepare.ps1"
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$common = @('/nologo','/platform:anycpu','/langversion:5','/unsafe+',"/win32manifest:$src\app.manifest",
  "/r:$src\lib\KeePassLib.dll",'/r:System.Windows.Forms.dll','/r:System.Drawing.dll',
  '/r:System.Web.Extensions.dll','/r:System.Security.dll','/r:System.IO.Compression.dll',
  '/r:System.IO.Compression.FileSystem.dll',"/resource:$src\defaults.json,defaults.json",
  "/resource:$src\help.html,help.html","/resource:$src\THIRD-PARTY.md,THIRD-PARTY.md",
  "/resource:$src\lib\KeePassLib.dll,KeePassLib.dll")
foreach ($file in Get-ChildItem "$src\browser" -File) {
  if ($file.Extension -in '.json','.js','.html','.png' -or $file.Name -eq 'winup-firefox.xpi') { $common += "/resource:$($file.FullName),browser/$($file.Name)" }
}
$sources = @((Get-ChildItem $src -Filter '*.cs').FullName) + "$src\Properties\AssemblyInfo.cs"
$common += "/resource:$src\file-engine\file-engine.zip,file-engine.zip", "/resource:$src\file-engine\file-engine.json,file-engine.json"
$common += "/resource:$src\file-engine\winfsp.msi,winfsp.msi"
foreach ($module in 'WinUp.PasskeyEngine','BouncyCastle.Cryptography','CBOR','Numbers') { $common += "/resource:$src\lib\$module.dll,$module.dll" }
$common += "/r:$src\lib\WinUp.PasskeyEngine.dll"
$common += "/resource:$src\public-suffix-list.dat,public-suffix-list.dat"
$common += "/resource:$src\updates\components.json,components.json","/resource:$src\updates\publisher.xml,component-publisher.xml"
foreach($file in Get-ChildItem "$src\licenses" -File) { $common += "/resource:$($file.FullName),licenses/$($file.Name)" }
foreach($name in 'WinUp.Passkeys.msix','WinUp.Passkeys.cer','package.json','Logo.png','setup.ps1','WinUp.PasskeyProvider.exe'){$common += "/resource:$src\system-passkeys\$name,system-passkeys/$name"}
function BuildCsvExportProbe {
    & $csc @common '/target:exe' '/main:WinUp.CsvExportProbe' "/out:$Output\CsvExportProbe.exe" "/r:$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Microsoft.VisualBasic.dll" @sources "$PSScriptRoot\CsvExportProbe.cs"
    if ($LASTEXITCODE) { throw 'CSV export probe build failed' }
}
if ($CsvExportOnly) { BuildCsvExportProbe; return }
function BuildHostNativeReview {
    New-Item -ItemType Directory -Force "$Output\host-native-review"|Out-Null
    & $csc @common '/target:winexe' '/main:WinUp.HostNativeReview' "/out:$Output\host-native-review\WinUp.exe" @sources "$PSScriptRoot\HostNativeReview.cs" "$PSScriptRoot\NativeResponseProbe.cs"
    if($LASTEXITCODE){throw 'Host native review build failed'}
}
if($HostNativeReviewOnly){BuildHostNativeReview;return}
function BuildSystemProviderProbe {
    & $csc @common '/target:exe' '/main:WinUp.SystemProviderProbe' "/out:$Output\SystemProviderProbe.exe" @sources "$PSScriptRoot\SystemProviderProbe.cs" "$PSScriptRoot\NativeResponseProbe.cs"
    if ($LASTEXITCODE) { throw 'System provider probe build failed' }
}
if($SystemProviderOnly){BuildSystemProviderProbe;return}
function BuildPackageSecurityProbe {
    & $csc @common '/target:exe' '/main:WinUp.PackageSecurityProbe' "/out:$Output\PackageSecurityProbe.exe" @sources "$PSScriptRoot\PackageSecurityProbe.cs"
    if($LASTEXITCODE){throw 'Package security probe build failed'}
}
if($PackageSecurityOnly){BuildPackageSecurityProbe;return}
function BuildFollowupSecurityProbe {
    & $csc @common '/target:exe' '/main:WinUp.FollowupSecurityProbe' "/out:$Output\FollowupSecurityProbe.exe" @sources "$PSScriptRoot\FollowupSecurityProbe.cs"
    if($LASTEXITCODE){throw 'Follow-up security probe build failed'}
}
if($FollowupSecurityOnly){BuildFollowupSecurityProbe;return}
function BuildFileWorkflowProbe {
    & $csc @common '/target:exe' '/main:WinUp.FileWorkflowProbe' "/out:$Output\FileWorkflowProbe.exe" @sources "$PSScriptRoot\FileWorkflowProbe.cs"
    if ($LASTEXITCODE) { throw 'File workflow probe build failed' }
}
if($FileWorkflowsOnly){BuildFileWorkflowProbe;return}
if($SecurityReviewOnly){
    & $csc @common '/target:exe' '/main:WinUp.SecurityHarness' "/out:$Output\SecurityHarness.exe" @sources "$PSScriptRoot\SecurityHarness.cs" "$PSScriptRoot\HardeningTests.cs" "$PSScriptRoot\FeatureTests.cs" "$PSScriptRoot\CorrectionsTests.cs" "$PSScriptRoot\UpdateTests.cs" "$PSScriptRoot\DeepStorageTests.cs" "$PSScriptRoot\DeepBrowserTests.cs" "$PSScriptRoot\DeepFileTests.cs" "$PSScriptRoot\DeliveryTests.cs" "$PSScriptRoot\OriginSecurityTests.cs"
    if($LASTEXITCODE){throw 'Security review build failed'}
    return
}
& $csc @common '/target:winexe' "/out:$Output\WinUp.exe" @sources
if ($LASTEXITCODE) { throw 'Production build failed' }
& $csc @common '/target:exe' '/main:WinUp.SecurityHarness' "/out:$Output\SecurityHarness.exe" @sources "$PSScriptRoot\SecurityHarness.cs" "$PSScriptRoot\HardeningTests.cs" "$PSScriptRoot\FeatureTests.cs" "$PSScriptRoot\CorrectionsTests.cs" "$PSScriptRoot\UpdateTests.cs" "$PSScriptRoot\DeepStorageTests.cs" "$PSScriptRoot\DeepBrowserTests.cs" "$PSScriptRoot\DeepFileTests.cs" "$PSScriptRoot\DeliveryTests.cs" "$PSScriptRoot\OriginSecurityTests.cs"
if ($LASTEXITCODE) { throw 'Harness build failed' }
New-Item -ItemType Directory -Force "$Output\browser-lab" | Out-Null
& $csc @common '/target:winexe' '/main:WinUp.FeatureUiHarness' "/out:$Output\browser-lab\WinUp.exe" @sources "$PSScriptRoot\FeatureUiHarness.cs"
if ($LASTEXITCODE) { throw 'Browser lab build failed' }
& $csc @common '/target:exe' '/main:WinUp.ComponentRuntimeProbe' "/out:$Output\ComponentRuntimeProbe.exe" @sources "$PSScriptRoot\ComponentRuntimeProbe.cs"
if ($LASTEXITCODE) { throw 'Component runtime probe build failed' }
BuildFileWorkflowProbe
BuildPackageSecurityProbe
BuildFollowupSecurityProbe
& $csc @common '/target:winexe' '/main:WinUp.FileWorkflowProbe' "/out:$Output\FileUiProbe.exe" @sources "$PSScriptRoot\FileWorkflowProbe.cs"
if ($LASTEXITCODE) { throw 'File UI probe build failed' }
BuildCsvExportProbe
& $csc @common '/target:exe' '/main:WinUp.AdvancedWorkflowProbe' "/out:$Output\AdvancedWorkflowProbe.exe" @sources "$PSScriptRoot\AdvancedWorkflowProbe.cs"
if ($LASTEXITCODE) { throw 'Advanced workflow probe build failed' }
BuildSystemProviderProbe
if($HostNativeReview){BuildHostNativeReview}
& $csc @common '/target:exe' '/main:WinUp.AdvancedUiProbe' "/out:$Output\AdvancedUiProbe.exe" @sources "$PSScriptRoot\AdvancedUiProbe.cs"
if ($LASTEXITCODE) { throw 'Advanced UI probe build failed' }
& $csc '/nologo' '/target:exe' "/out:$Output\MemoryProbe.exe" "$PSScriptRoot\MemoryProbe.cs"
if ($LASTEXITCODE) { throw 'Memory probe build failed' }
& $csc '/nologo' '/target:exe' "/out:$Output\SyntheticInstaller.exe" "$PSScriptRoot\SyntheticInstaller.cs"
if ($LASTEXITCODE) { throw 'Synthetic installer build failed' }
& $csc '/nologo' '/target:winexe' '/r:System.Windows.Forms.dll' "/out:$Output\DesktopWindowFixture.exe" "$PSScriptRoot\DesktopWindowFixture.cs"
if ($LASTEXITCODE) { throw 'Desktop window fixture build failed' }
Copy-Item "$Output\DesktopWindowFixture.exe" "$Output\ForeignWindowFixture.exe" -Force

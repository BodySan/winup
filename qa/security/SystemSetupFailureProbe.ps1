param([string]$Source,[string]$Baseline,[string]$Output)
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -and $env:GITHUB_ACTIONS -ne 'true'){throw 'Disposable Sandbox or CI only'}
$taskLab='C:\WinUpAudit\setup-failure-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$taskCurrent=Join-Path $taskLab 'current'
$taskOld=Join-Path $taskLab 'old'
New-Item -ItemType Directory -Path (Join-Path $taskCurrent 'system-passkeys'),(Join-Path $taskOld 'system-passkeys') -Force|Out-Null
foreach($taskName in 'WinUp.Passkeys.msix','WinUp.Passkeys.cer','package.json'){
 Copy-Item -LiteralPath (Join-Path $Source ('system-passkeys\'+$taskName)) -Destination (Join-Path $taskCurrent ('system-passkeys\'+$taskName))
}
[IO.File]::WriteAllText((Join-Path $taskOld 'system-passkeys\WinUp.Passkeys.msix'),'untrusted old package fixture')
$global:WinUpSetupProbeCalls=New-Object Collections.Generic.List[string]
function Get-ItemProperty {param($LiteralPath,$ErrorAction) [pscustomobject]@{Root=$taskOld;PackageHash='old-hash'}}
function Get-AppxPackage {param($Name) [pscustomobject]@{Name='WinUp.Passkeys'}}
function Remove-AppxPackage {param([Parameter(ValueFromPipeline=$true)]$Package) process{}}
function Add-AppxPackage {param($Path,$ExternalLocation) $global:WinUpSetupProbeCalls.Add($Path);throw 'Synthetic installation failure'}
function Start-Process {throw 'Unexpected helper launch in a failure scenario'}
$taskLines=New-Object Collections.Generic.List[string]
if($Baseline){
 try{& $Baseline -Root $taskCurrent -Mode install}catch{$taskLines.Add('BASELINE exception: '+$_.Exception.Message)}
 $taskBaselineOk=$global:WinUpSetupProbeCalls.Contains((Join-Path $taskOld 'system-passkeys\WinUp.Passkeys.msix'))
 $taskLines.Add(('BASELINE old-package-attempted='+$taskBaselineOk))
 $global:WinUpSetupProbeCalls.Clear()
}
try{& (Join-Path $Source 'system-passkeys\setup.ps1') -Root $taskCurrent -Mode install}catch{$taskLines.Add('CURRENT exception: '+$_.Exception.Message)}
$taskOk=$global:WinUpSetupProbeCalls.Count -eq 1 -and $global:WinUpSetupProbeCalls[0] -eq (Join-Path $taskCurrent 'system-passkeys\WinUp.Passkeys.msix')
$taskLines.Add($(if($taskOk){'PASS setup-failure-does-not-install-old-untrusted-package'}else{'FAIL setup-failure-used-untrusted-package'}))
if($Output){[IO.File]::WriteAllLines($Output,$taskLines)}
$taskLines
Remove-Variable -Name WinUpSetupProbeCalls -Scope Global
if(!$taskOk -or $Baseline -and !$taskBaselineOk){throw 'Setup failure check did not reproduce the expected before/after behavior'}

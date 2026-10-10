param([Parameter(Mandatory=$true)][string]$Root,[ValidateSet('install','remove')][string]$Mode='install')
$ErrorActionPreference='Stop'
# Load the Windows PowerShell module explicitly; Get-FileHash can otherwise be
# unavailable when WinUp inherits a module search path from another PowerShell.
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$Root=[IO.Path]::GetFullPath($Root)
$package=Join-Path $Root 'system-passkeys\WinUp.Passkeys.msix'
$meta=Get-Content -LiteralPath (Join-Path $Root 'system-passkeys\package.json') -Raw -Encoding UTF8|ConvertFrom-Json
$cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $Root 'system-passkeys\WinUp.Passkeys.cer'))
if($meta.schema -ne 1 -or $cert.Subject -ne 'CN=WinUp' -or $cert.Thumbprint -ne $meta.thumbprint -or (Get-FileHash -LiteralPath $package).Hash -ne $meta.packageHash){throw 'Пакет подключения к Windows изменён.'}
if($Mode -eq 'remove'){
 $process=Start-Process -FilePath (Join-Path $Root 'system-passkeys\WinUp.PasskeyProvider.exe') -ArgumentList '--system-passkey-remove-quiet' -WindowStyle Hidden -PassThru
 [void]$process.Handle
 if(!$process.WaitForExit(30000)){$process.Kill();throw 'Windows не завершила отключение провайдера.'}
 if($process.ExitCode -lt 0){throw ('Windows не отключила провайдер. Код: 0x'+$process.ExitCode.ToString('X8'))}
 Get-AppxPackage -Name WinUp.Passkeys|Remove-AppxPackage
 $registration='HKCU:\Software\WinUp\SystemPasskeys'
 $current=Get-ItemProperty -LiteralPath $registration -ErrorAction SilentlyContinue
 if($current -and $current.Root -eq $Root){Remove-Item -LiteralPath $registration}
 Write-Output 'WinUp отключён от Windows. Ключи в базе сохранены.'
}else{
 $registration='HKCU:\Software\WinUp\SystemPasskeys'
 $old=Get-ItemProperty -LiteralPath $registration -ErrorAction SilentlyContinue
 $installed=Get-AppxPackage -Name WinUp.Passkeys
 if(!$installed -or !$old -or $old.Root -ne $Root -or $old.PackageHash -ne $meta.packageHash){
  if($installed){$installed|Remove-AppxPackage}
  try{Add-AppxPackage -Path $package -ExternalLocation $Root}catch{
   # An old registry path is not a source of trusted package bytes. Restore a
   # previous connection explicitly from that copy of WinUp after a failed move.
   throw
  }
  New-Item -Path $registration -Force|Out-Null
  New-ItemProperty -LiteralPath $registration -Name Root -Value $Root -PropertyType String -Force|Out-Null
  New-ItemProperty -LiteralPath $registration -Name PackageHash -Value $meta.packageHash -PropertyType String -Force|Out-Null
 }
 $process=Start-Process -FilePath (Join-Path $Root 'system-passkeys\WinUp.PasskeyProvider.exe') -ArgumentList '--system-passkey-register-quiet' -WindowStyle Hidden -PassThru
 [void]$process.Handle
 if(!$process.WaitForExit(30000)){$process.Kill();throw 'Windows не завершила регистрацию провайдера.'}
 if($process.ExitCode -lt 0 -and $process.ExitCode -ne -2146893809){throw ('Windows не зарегистрировала провайдер. Код: 0x'+$process.ExitCode.ToString('X8'))}
 Write-Output 'WinUp подключён. Включите его в дополнительных параметрах ключей доступа Windows.'
}

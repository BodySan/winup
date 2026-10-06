param([ValidateSet('baseline','candidate')][string]$Variant = 'candidate')
$ErrorActionPreference = 'Stop'
$lab = "C:\WinUpAudit\$Variant"
$output = "C:\WinUp\test\audit\$Variant"
try {
  foreach ($marker in 'finished.txt','runner-error.txt') {
    $markerPath = Join-Path $output $marker
    if (Test-Path -LiteralPath $markerPath) { Remove-Item -LiteralPath $markerPath }
  }
  New-Item -ItemType Directory -Force $lab | Out-Null
  Copy-Item "$output\WinUp.exe","$output\SecurityHarness.exe","$output\MemoryProbe.exe" $lab -Force
  Copy-Item 'C:\WinUp\test\audit\official-KeePass.zip','C:\WinUp\test\audit\official-KeePass.exe' $lab -Force
  $info = New-Object Diagnostics.ProcessStartInfo
  $info.FileName = "$lab\SecurityHarness.exe"
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $p = New-Object Diagnostics.Process
  $p.StartInfo = $info
  [void]$p.Start()
  $stdout = $p.StandardOutput.ReadToEndAsync()
  $stderr = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit(180000)) { $p.Kill(); throw 'Harness timed out after 180 seconds' }
  $stdout.Result | Set-Content "$output\runtime.txt"
  $stderr.Result | Set-Content "$output\errors.txt"
  "exit=$($p.ExitCode)" | Set-Content "$output\finished.txt"
} catch { $_ | Out-String | Set-Content "$output\runner-error.txt" }

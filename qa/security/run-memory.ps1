foreach ($variant in 'memory-baseline','memory-candidate') {
  $lab = "C:\WinUpAudit\$variant"
  New-Item -ItemType Directory -Force $lab | Out-Null
  Copy-Item "C:\WinUp\test\audit\$variant\*.exe" $lab -Force
  & "$lab\SecurityHarness.exe" *> "C:\WinUp\test\audit\$variant\runtime.txt"
  "exit=$LASTEXITCODE" | Add-Content "C:\WinUp\test\audit\$variant\runtime.txt"
}

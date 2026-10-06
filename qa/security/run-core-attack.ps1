$ErrorActionPreference='Stop'
foreach($variant in 'baseline','candidate') {
  $lab="C:\WinUpAudit\core-attack-$variant"
  New-Item -ItemType Directory -Force $lab | Out-Null
  Copy-Item 'C:\WinUp\test\audit\CoreAttack.exe' $lab -Force
  Copy-Item 'C:\WinUp\test\audit\fake-core\KeePassLib.dll' "$lab\fake-core.dll" -Force
  $exe=if($variant -eq 'baseline'){'C:\WinUp\test\audit\memory-baseline\WinUp.exe'}else{'C:\WinUp\test\audit\candidate\WinUp.exe'}
  Copy-Item $exe "$lab\WinUp.exe" -Force
  & "$lab\CoreAttack.exe" *> "C:\WinUp\test\audit\core-attack-$variant.txt"
  "exit=$LASTEXITCODE" | Add-Content "C:\WinUp\test\audit\core-attack-$variant.txt"
}

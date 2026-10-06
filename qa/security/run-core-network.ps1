$ErrorActionPreference='Stop'
$lab='C:\WinUpAudit\core-network'
New-Item -ItemType Directory -Force $lab | Out-Null
Copy-Item 'C:\WinUp\test\audit\CoreNetworkProbe.exe','C:\WinUp\test\audit\candidate\WinUp.exe' $lab -Force
& "$lab\CoreNetworkProbe.exe" *> 'C:\WinUp\test\audit\core-network.txt'
"exit=$LASTEXITCODE" | Add-Content 'C:\WinUp\test\audit\core-network.txt'

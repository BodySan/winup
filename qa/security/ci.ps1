param([string]$Source,[string]$Output='C:\WinUp\test\ci\candidate')
$ErrorActionPreference='Stop'
if(!$Source) { $Source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\src')) }
$lab='C:\WinUpAudit\ci-'+[Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Force $lab,$Output | Out-Null
& "$PSScriptRoot\build.ps1" -Source $Source -Output $Output
Copy-Item "$Output\SecurityHarness.exe","$Output\MemoryProbe.exe" $lab
$fixture=Join-Path $PSScriptRoot '..\fixtures\KeePass-2.61.1.zip'
if((Get-FileHash -LiteralPath $fixture).Hash -ne '3952354DB9B117E906F7CD4F9F5591065B95186472370DA47F46F3E246FEA864') { throw 'Official KeePass test fixture digest mismatch.' }
Copy-Item -LiteralPath $fixture -Destination "$lab\official-KeePass.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
if(!(Test-Path 'C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll')) {
    $msi=Join-Path $Source 'file-engine\winfsp.msi'
    $signature=Get-AuthenticodeSignature -LiteralPath $msi
    if((Get-FileHash -LiteralPath $msi).Hash -ne '073A70E00F77423E34BED98B86E600DEF93393BA5822204FAC57A29324DB9F7A' -or $signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'NAVIMATICS LLC') { throw 'Untrusted WinFsp fixture.' }
    $installer=Start-Process msiexec.exe -ArgumentList @('/i',('"'+$msi+'"'),'/qn','/norestart') -WindowStyle Hidden -PassThru -Wait
    if($installer.ExitCode -notin 0,3010) { throw 'WinFsp installation on disposable runner failed.' }
}
$archive=[IO.Compression.ZipFile]::OpenRead($fixture)
try {
    $entry=$archive.GetEntry('KeePass.exe'); if(!$entry) { throw 'KeePass executable absent.' }
    $input=$entry.Open(); $outputStream=[IO.File]::Create("$lab\official-KeePass.exe")
    try { $input.CopyTo($outputStream) } finally { $input.Dispose(); $outputStream.Dispose() }
} finally { $archive.Dispose() }
$info=[Diagnostics.ProcessStartInfo]::new("$lab\SecurityHarness.exe")
$info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
$process=[Diagnostics.Process]::new(); $process.StartInfo=$info; [void]$process.Start()
$stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
if(!$process.WaitForExit(180000)) { $process.Kill(); throw 'Security harness timeout.' }
$stdout.Result | Set-Content "$Output\runtime.txt"; $stderr.Result | Set-Content "$Output\errors.txt"
if($process.ExitCode -or $stdout.Result -notmatch 'TOTAL failures=0') { throw "Security tests failed. Read $Output\runtime.txt" }
$env:WINUP_TEST_BROWSER_SOURCE=Join-Path $Source 'browser'
try { & node "$PSScriptRoot\extension-tests.cjs"; if($LASTEXITCODE) { throw 'Browser JS tests failed.' } }
finally { Remove-Item Env:WINUP_TEST_BROWSER_SOURCE -ErrorAction SilentlyContinue }
Write-Output 'PASS all production-source security and browser JS tests'

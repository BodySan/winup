param([string]$Source,[string]$Output='C:\WinUp\test\ci\candidate',[switch]$FunctionalOnly)
$ErrorActionPreference='Stop'
if(!$Source) { $Source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\src')) }
$lab='C:\WinUpAudit\ci-'+[Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Force $lab,$Output | Out-Null
& "$PSScriptRoot\build.ps1" -Source $Source -Output $Output
Copy-Item "$Output\WinUp.exe","$Output\SecurityHarness.exe","$Output\MemoryProbe.exe","$Output\SyntheticInstaller.exe" $lab
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
if($FunctionalOnly){$info.Arguments='--functional-only'}
$info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
$process=[Diagnostics.Process]::new(); $process.StartInfo=$info; [void]$process.Start()
$stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
if(!$process.WaitForExit(600000)) { $process.Kill(); throw 'Test harness timeout.' }
$stdout.Result | Set-Content "$Output\runtime.txt"; $stderr.Result | Set-Content "$Output\errors.txt"
if($process.ExitCode -or $stdout.Result -notmatch 'TOTAL failures=0') { throw "Tests failed. Read $Output\runtime.txt" }
if($env:GITHUB_ACTIONS -eq 'true') {
    $fileLab='C:\WinUpAudit\fci-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
    New-Item -ItemType Directory $fileLab|Out-Null
    Copy-Item -LiteralPath "$Output\SystemProviderProbe.exe" -Destination $fileLab
    $nativeProbe=Start-Process -FilePath "$fileLab\SystemProviderProbe.exe" -ArgumentList '--ci','--encoding-only' -WindowStyle Hidden -PassThru -RedirectStandardOutput "$Output\native-encoding.txt" -RedirectStandardError "$Output\native-errors.txt"
    [void]$nativeProbe.Handle
    if(!$nativeProbe.WaitForExit(30000)){$nativeProbe.Kill();throw 'Native response encoding timeout'}
    if($nativeProbe.ExitCode -eq 0){
        & node "$PSScriptRoot\..\tests\native-response-probe.cjs" $fileLab | Tee-Object -FilePath "$Output\native-response.txt"
        if($LASTEXITCODE){throw 'Windows native response verification failed'}
    }elseif($nativeProbe.ExitCode -eq 3 -and [IO.File]::ReadAllText("$Output\native-encoding.txt") -match '^SKIP native response encoding:'){
        Write-Output 'Native response encoding requires a newer Windows API than this runner provides.'
    }else{throw 'Windows native response encoding failed'}
    Copy-Item -LiteralPath "$Output\FileWorkflowProbe.exe" -Destination $fileLab
    $fileProbe=Start-Process -FilePath "$fileLab\FileWorkflowProbe.exe" -ArgumentList '--ci' -WindowStyle Hidden -PassThru -RedirectStandardOutput "$Output\file-workflows.txt" -RedirectStandardError "$Output\file-errors.txt"
    if(!$fileProbe.WaitForExit(600000)){$fileProbe.Kill();throw 'File workflows timeout'}
    $fileResult=[IO.File]::ReadAllText("$Output\file-workflows.txt")
    if($fileResult -notmatch 'RESULT passed=\d+ failed=0'){throw 'File workflows failed; nothing is ready for release'}
    Copy-Item -LiteralPath "$Output\AdvancedWorkflowProbe.exe" -Destination $fileLab
    $advanced=Start-Process -FilePath "$fileLab\AdvancedWorkflowProbe.exe" -ArgumentList '--ci' -WindowStyle Hidden -PassThru -RedirectStandardOutput "$Output\advanced-workflows.txt" -RedirectStandardError "$Output\advanced-errors.txt"
    [void]$advanced.Handle
    if(!$advanced.WaitForExit(600000)){$advanced.Kill();throw 'Advanced workflows timeout'}
    if($advanced.ExitCode -ne 0 -or [IO.File]::ReadAllText("$Output\advanced-workflows.txt") -notmatch 'RESULT passed=\d+ failed=0'){throw 'Advanced workflows failed; nothing is ready for release'}
    $layoutProbe=Start-Process -FilePath "$fileLab\FileWorkflowProbe.exe" -ArgumentList '--ci','--layout' -WindowStyle Hidden -PassThru -RedirectStandardOutput "$Output\layout.txt" -RedirectStandardError "$Output\layout-errors.txt"
    # Cache the process handle before waiting: Windows PowerShell may otherwise
    # leave ExitCode null even though the redirected checks finished successfully.
    [void]$layoutProbe.Handle
    if(!$layoutProbe.WaitForExit(120000)){$layoutProbe.Kill();throw 'Action layout timeout'}
    if($layoutProbe.ExitCode -ne 0 -or [IO.File]::ReadAllText("$Output\layout.txt") -notmatch 'PASS layout all'){throw 'Action layout checks failed'}
}
if($FunctionalOnly) {
    & node "$PSScriptRoot\..\tests\passkey-focus-regression.cjs"
    if($LASTEXITCODE){throw 'Native passkey focus regression failed.'}
    & node "$PSScriptRoot\..\tests\passkey-visibility-regression.cjs"
    if($LASTEXITCODE){throw 'Passkey visibility regression failed.'}
    foreach($script in Get-ChildItem -LiteralPath (Join-Path $Source 'browser') -Filter '*.js') {
        & node --check $script.FullName
        if($LASTEXITCODE){throw "Extension syntax error: $($script.Name)"}
    }
    Write-Output 'PASS functional application regressions and extension syntax';return
}
$env:WINUP_TEST_BROWSER_SOURCE=Join-Path $Source 'browser'
try { & node "$PSScriptRoot\extension-tests.cjs"; if($LASTEXITCODE) { throw 'Browser JS tests failed.' } }
finally { Remove-Item Env:WINUP_TEST_BROWSER_SOURCE -ErrorAction SilentlyContinue }
Write-Output 'PASS all production-source security and browser JS tests'

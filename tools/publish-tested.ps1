param([string]$Gh='gh',[string]$ProtectedKey,[string]$Repository='BodySan/winup',[switch]$Refresh,[switch]$PrepareOnly,[long]$TestRunId)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if(!$ProtectedKey) { $ProtectedKey=Join-Path $root '.release-private\component-signing.dpapi' }
if(!(Test-Path -LiteralPath $ProtectedKey)) { throw 'The local release signing key is absent. Use the original Windows account and its protected key backup.' }
$envSet=$false
try {
    if(!$env:GH_TOKEN) {
        $info=[Diagnostics.ProcessStartInfo]::new('git','-c credential.interactive=never credential fill')
        $info.UseShellExecute=$false; $info.RedirectStandardInput=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true; $info.CreateNoWindow=$true
        $info.EnvironmentVariables['GIT_TERMINAL_PROMPT']='0'
        $process=[Diagnostics.Process]::new(); $process.StartInfo=$info; [void]$process.Start()
        $process.StandardInput.Write("protocol=https`nhost=github.com`n`n"); $process.StandardInput.Close()
        $credential=$process.StandardOutput.ReadToEnd(); $diagnostics=$process.StandardError.ReadToEnd(); $process.WaitForExit()
        if($process.ExitCode) { throw 'Sign in to GitHub with gh auth login or Git Credential Manager.' }
        $env:GH_TOKEN=($credential -split "`n" | Where-Object { $_.StartsWith('password=') } | Select-Object -First 1).Substring(9).Trim(); $credential=$null; $envSet=$true
    }
    if($Refresh) {
        if($TestRunId) { throw 'Choose Refresh or TestRunId, not both.' }
        $before=& $Gh run list --repo $Repository --workflow components.yml --branch main --limit 1 --json databaseId | ConvertFrom-Json
        if($LASTEXITCODE) { throw 'Workflow listing failed.' }
        $last=if($before) { [long]@($before)[0].databaseId } else { 0 }
        & $Gh workflow run components.yml --repo $Repository --ref main
        if($LASTEXITCODE) { throw 'Component checks could not be started.' }
        Write-Output 'Waiting for fresh GitHub checks. The signing key remains local.'
        $deadline=[DateTime]::UtcNow.AddMinutes(20); $finished=$false
        while([DateTime]::UtcNow -lt $deadline) {
            $current=& $Gh run list --repo $Repository --workflow components.yml --branch main --limit 1 --json databaseId,status,conclusion | ConvertFrom-Json
            if($LASTEXITCODE) { throw 'Cannot read check status.' }
            $latest=@($current)[0]
            if($latest -and [long]$latest.databaseId -gt $last -and $latest.status -eq 'completed') {
                if($latest.conclusion -ne 'success') { throw 'Fresh checks failed. Nothing was signed or published.' }
                $TestRunId=[long]$latest.databaseId; $finished=$true; break
            }
            Start-Sleep -Seconds 10
        }
        if(!$finished) { throw 'Check timeout. Nothing was signed or published.' }
    }
    if($TestRunId) {
        $run=& $Gh run view $TestRunId --repo $Repository --json databaseId,number,headSha,event,conclusion,headBranch,workflowName,status | ConvertFrom-Json
    } else {
        $runs=& $Gh run list --repo $Repository --workflow components.yml --branch main --limit 20 --json databaseId,number,headSha,event,conclusion,headBranch,workflowName,status | ConvertFrom-Json
        $run=@($runs | Where-Object { $_.status -eq 'completed' -and $_.conclusion -eq 'success' })[0]
    }
    if($LASTEXITCODE -or !$run) { throw 'No successfully checked component candidate on main.' }
    if($run.status -ne 'completed' -or $run.conclusion -ne 'success' -or $run.headBranch -ne 'main' -or $run.workflowName -ne 'Проверить компоненты' -or $run.event -notin 'workflow_dispatch','schedule') { throw 'Unexpected workflow run; refusing release.' }
    Write-Output "Verified test run $($run.databaseId), commit $($run.headSha)."
    $sequence=100000+[long]$run.number
    $existing=& $Gh release list --repo $Repository --json tagName | ConvertFrom-Json
    if($LASTEXITCODE) { throw 'Release listing failed.' }
    if($existing.tagName -contains "components-$sequence") { Write-Output 'This tested candidate is already published.'; return }
    $folder=Join-Path $root ('release-work\'+[Guid]::NewGuid().ToString('N'))
    $candidate=Join-Path $folder 'src'; $release=Join-Path $folder 'release'
    New-Item -ItemType Directory -Force $candidate,$release | Out-Null
    & $Gh run download $run.databaseId --repo $Repository --name tested-source --dir $candidate
    if($LASTEXITCODE) { throw 'Candidate download failed.' }
    & "$PSScriptRoot\verify-candidate.ps1" -Candidate $candidate
    # Rebuild the application locally; the CI-provided EXE is not published blindly.
    & "$root\src\build.ps1" -Source $candidate -Output "$release\WinUp.exe"
    & "$root\src\updates\build-package.ps1" -Sequence $sequence -Source $candidate -Output $release -ProtectedKey $ProtectedKey
    Compress-Archive -Path "$candidate\*" -DestinationPath "$release\src.zip"
    $notes="Комплект №$sequence. Проверки GitHub Actions пройдены; подпись выполнена локально на ПК владельца. Новые совместимые библиотеки и PSL. Cryptomator/Java сохраняются в согласованном runtime. KeePass/WinFsp обновляются отдельными кнопками."
    [IO.File]::WriteAllText("$release\notes.txt",$notes,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $root 'release-ready.json'),(@{directory=$release;sequence=$sequence;commit=$run.headSha;repository=$Repository}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    if($PrepareOnly) {
        Write-Output "Prepared and locally signed release ${sequence}: $release"; return
    }
    & $Gh release create "components-$sequence" --repo $Repository --target $run.headSha --title "WinUp: комплект $sequence" --notes-file "$release\notes.txt" "$release\WinUp.exe" "$release\WinUp.exe.sig" "$release\src.zip" "$release\components.wup" "$release\update.json" "$release\update.sig"
    if($LASTEXITCODE) { throw 'Signed release publication failed.' }
    Write-Output "Published verified, locally signed component release $sequence. Restart WinUp after installing it."
} finally { if($envSet) { Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue }; $credential=$null }

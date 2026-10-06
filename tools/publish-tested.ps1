param([string]$Gh='gh',[string]$ProtectedKey,[string]$Repository='BodySan/winup')
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
    $runs=& $Gh run list --repo $Repository --workflow components.yml --status success --branch main --limit 1 --json databaseId,number,headSha,event,conclusion | ConvertFrom-Json
    if($LASTEXITCODE -or !$runs) { throw 'No successfully checked component candidate on main.' }
    $run=@($runs)[0]
    if($run.conclusion -ne 'success' -or $run.event -notin 'workflow_dispatch','schedule') { throw 'Unexpected workflow run; refusing release.' }
    $sequence=100000+[long]$run.number
    $existing=& $Gh release list --repo $Repository --json tagName | ConvertFrom-Json
    if($LASTEXITCODE) { throw 'Release listing failed.' }
    if($existing.tagName -contains "components-$sequence") { Write-Output 'This tested candidate is already published.'; return }
    $folder=Join-Path $root ('release-work\'+[Guid]::NewGuid().ToString('N'))
    $candidate=Join-Path $folder 'src'; $release=Join-Path $folder 'release'
    New-Item -ItemType Directory -Force $candidate,$release | Out-Null
    & $Gh run download $run.databaseId --repo $Repository --name tested-source --dir $candidate
    if($LASTEXITCODE) { throw 'Candidate download failed.' }
    & $Gh run download $run.databaseId --repo $Repository --name tested-executable --dir $release
    if($LASTEXITCODE) { throw 'Executable download failed.' }
    # Execute only local publisher scripts. Downloaded candidate code is never run here.
    & "$root\src\updates\build-package.ps1" -Sequence $sequence -Source $candidate -Output $release -ProtectedKey $ProtectedKey
    Compress-Archive -Path "$candidate\*" -DestinationPath "$release\src.zip"
    $notes="Комплект №$sequence. Проверки GitHub Actions пройдены; подпись выполнена локально на ПК владельца. Новые совместимые библиотеки и PSL. Cryptomator/Java сохраняются в согласованном runtime. KeePass/WinFsp обновляются отдельными кнопками."
    [IO.File]::WriteAllText("$release\notes.txt",$notes,[Text.UTF8Encoding]::new($false))
    & $Gh release create "components-$sequence" --repo $Repository --target $run.headSha --title "WinUp: комплект $sequence" --notes-file "$release\notes.txt" "$release\WinUp.exe" "$release\src.zip" "$release\components.wup" "$release\update.json" "$release\update.sig"
    if($LASTEXITCODE) { throw 'Signed release publication failed.' }
    Write-Output "Published verified, locally signed component release $sequence. Restart WinUp after installing it."
} finally { if($envSet) { Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue }; $credential=$null }

param([Parameter(Mandatory=$true)][string]$Candidate,[Parameter(Mandatory=$true)][string]$Trusted,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
if((Get-FileHash -LiteralPath $Candidate).Hash -eq (Get-FileHash -LiteralPath $Trusted).Hash){Write-Output 'PSL matches the trusted bundled snapshot.';return}
$taskText=[IO.File]::ReadAllText($Candidate,[Text.Encoding]::UTF8)
$taskBaseline=[IO.File]::ReadAllText($Trusted,[Text.Encoding]::UTF8)
$taskVersions=[regex]::Matches($taskText,'(?m)^// VERSION: (\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_UTC)\r?$')
$taskCommits=[regex]::Matches($taskText,'(?m)^// COMMIT: ([a-f0-9]{40})\r?$')
$taskBundled=[regex]::Match($taskBaseline,'(?m)^// VERSION: (\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_UTC)').Groups[1].Value
if($taskVersions.Count -ne 1 -or $taskCommits.Count -ne 1 -or !$taskBundled){throw 'Invalid PSL provenance headers.'}
$taskStamp=$taskVersions[0].Groups[1].Value;$taskCommit=$taskCommits[0].Groups[1].Value
if([string]::CompareOrdinal($taskStamp,$taskBundled) -lt 0){throw 'Candidate PSL is older than the trusted baseline.'}
$taskDate=[DateTime]::ParseExact($taskStamp,'yyyy-MM-dd_HH-mm-ss_\U\T\C',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
if($taskDate -gt [DateTime]::UtcNow.AddMinutes(5)){throw 'Candidate PSL has a future timestamp.'}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$taskHeaders=@{'User-Agent'='WinUp-local-release'}
$taskComparison=Invoke-RestMethod -Uri ('https://api.github.com/repos/publicsuffix/list/compare/'+$taskCommit+'...main') -Headers $taskHeaders
if($taskComparison.merge_base_commit.sha -ne $taskCommit -or $taskComparison.status -notin 'ahead','identical'){throw 'PSL commit is not in the official main history.'}
$taskCommitDate=[DateTimeOffset]::Parse([string]$taskComparison.base_commit.commit.committer.date,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime
if($taskDate -lt $taskCommitDate.AddMinutes(-5) -or $taskDate -gt $taskCommitDate.AddDays(1)){throw 'PSL publication stamp does not match the official commit date.'}
Invoke-WebRequest -Uri ('https://raw.githubusercontent.com/publicsuffix/list/'+$taskCommit+'/public_suffix_list.dat') -OutFile $Output -UseBasicParsing
function Canonical([string]$Value) {
 # The publicsuffix.org deployment adds exactly these provenance comments.
 # Blank lines have no PSL meaning; all other content must match upstream.
 return (($Value -split '\r?\n' | Where-Object {$_.Trim().Length -gt 0 -and $_ -notmatch '^// (VERSION|COMMIT):'}) -join "`n")
}
if((Canonical $taskText) -cne (Canonical ([IO.File]::ReadAllText($Output,[Text.Encoding]::UTF8)))){throw 'Candidate PSL content differs from the immutable official commit.'}
Write-Output ('PSL verified against official main-history commit '+$taskCommit+'; no CDN snapshot race.')

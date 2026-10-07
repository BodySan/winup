param([string]$Source=(Join-Path $PSScriptRoot 'manual.src.html'),[string]$Shots=(Join-Path $PSScriptRoot 'shots-1.15'))
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Web
$taskManual=[IO.File]::ReadAllText($Source,[Text.Encoding]::UTF8)
$taskPattern='<!--IMG:([^|]+)\|([^>]*?)-->'
$taskMissing=@()
foreach($taskMarker in [regex]::Matches($taskManual,$taskPattern)) {
 $taskName=$taskMarker.Groups[1].Value
 if($taskName -notmatch '^[a-z0-9-]+$'){throw "Invalid screenshot name: $taskName"}
 if(!(Test-Path -LiteralPath (Join-Path $Shots ($taskName+'.png')))){$taskMissing+=$taskName}
}
if($taskMissing.Count){throw ('Required current screenshots are missing: '+($taskMissing -join ', '))}
if($taskManual -match '<!--PHONE:'){throw 'Old phone screenshots are not part of this manual.'}
$taskOutput=[regex]::Replace($taskManual,$taskPattern,{
 param($taskMatch)
 $taskName=$taskMatch.Groups[1].Value
 $taskCaption=[Web.HttpUtility]::HtmlEncode($taskMatch.Groups[2].Value)
 $taskImage=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Shots ($taskName+'.png'))))
 '<figure><img alt="'+$taskCaption+'" loading="lazy" src="data:image/png;base64,'+$taskImage+'"><figcaption>'+$taskCaption+'</figcaption></figure>'
})
$taskOwner=[Environment]::UserName
if($taskOutput -match 'C:[/\\]Users[/\\]' -or ($taskOwner.Length -gt 3 -and $taskOutput -match [regex]::Escape($taskOwner))){throw 'Personal data or a user-profile path found in the manual.'}
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Инструкция.html'),$taskOutput,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $PSScriptRoot '..\src\help.html'),$taskOutput,[Text.UTF8Encoding]::new($false))
Write-Output ('Manual built with '+([regex]::Matches($taskOutput,'<figure>').Count)+' current screenshots.')

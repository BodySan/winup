$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Web
$taskProfiles=Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\src\browser\login-profiles.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$taskManualPath=Join-Path $PSScriptRoot 'manual-1.15.src.html'
$taskManual=[IO.File]::ReadAllText($taskManualPath,[Text.Encoding]::UTF8)
$taskRows=@('<tr><th>Сервис</th><th>Начало входа</th><th>Режим</th><th>Граница проверки</th></tr>')
$taskMarkdown=@('# Маршруты входа: состояние 8 октября 2026 года','','Публичные формы изучались без личных паролей. В таблице явно отмечена граница наблюдения; полный вход в каждый сервис не подтверждён. SMS, CAPTCHA и аппаратное подтверждение могут требовать действия владельца.','','| Сервис | Начало входа | Режим | Граница проверки |','|---|---|---|---|')
foreach($taskProfile in $taskProfiles | Sort-Object Id){
 $taskMode=switch($taskProfile.Mode){'none'{'Без автоматического входа'} 'manual'{'Ручной вход / внешний аккаунт'} 'form'{'Заполнение распознанной формы'} default{'Переходы по форме; возможен ручной шаг'}}
 $taskEvidence=if($taskProfile.Evidence){$taskProfile.Evidence}else{'Полный сценарий не подтверждён'}
 $taskValues=@($taskProfile.Id,$taskProfile.LoginUrl,$taskMode,$taskEvidence)
 $taskRows+='<tr>'+ (($taskValues | ForEach-Object {'<td>'+[Web.HttpUtility]::HtmlEncode($_)+'</td>'}) -join '')+'</tr>'
 $taskMarkdown+='| '+(($taskValues | ForEach-Object {$_ -replace '\|','\|' -replace '\r?\n',' '}) -join ' | ')+' |'
}
$taskTable='<!--LOGIN-ROUTES-BEGIN--><details id="login-routes"><summary>Маршруты входа и границы проверки: '+$taskProfiles.Count+' сервис</summary><p>Обследованы публичные страницы. Полный вход в каждый аккаунт не подтверждён этой таблицей. SMS, CAPTCHA и выбор внешнего провайдера выполняются вручную.</p><div class="table-wrap"><table>'+($taskRows -join '')+'</table></div></details><!--LOGIN-ROUTES-END-->'
$taskManual=[regex]::Replace($taskManual,'(?s)<!--LOGIN-ROUTES-BEGIN-->.*?<!--LOGIN-ROUTES-END-->',$taskTable)
[IO.File]::WriteAllText($taskManualPath,$taskManual,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'LOGIN-ROUTES-2026-10-08.md'),($taskMarkdown -join "`r`n"),[Text.UTF8Encoding]::new($false))
Write-Output ('Documented '+$taskProfiles.Count+' login profiles')

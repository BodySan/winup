$ErrorActionPreference='Stop'
$taskPath=Join-Path $PSScriptRoot '..\src\defaults.json'
$taskData=Get-Content -LiteralPath $taskPath -Raw -Encoding UTF8|ConvertFrom-Json
$taskCategories=[ordered]@{
 'Игры'='Battle.net|BlueStacks|Coop-Land|CYBERSHOKE|EA app|Epic Games Launcher|expose.gg|Faceit|GGSEL|GOG|Kupikod|MemeSense|Nexus Mods|NVIDIA|Plati.Market|PlayStation / Sony|Razer Synapse|Rockstar Games Launcher|Steam Community|SteamKey|TLauncher|Ubisoft Connect|VK Play'
 'Дом'='Ajax|ВсеИнструменты.ру|Hoff|Лемана ПРО|RemPlanner'
 'Еда'='Burger King|Chibbis|Echte Doner|Купер|Масленка|Пятёрочка / X5ID|Яндекс Еда'
 'Покупки'='Авито|DarkStore|DNS|ВсеМайки|М.Видео|Мегамаркет|Онлайн Трейд|Ozon|Сима-ленд|Ситилинк|Спортмастер|ТВОЕ|Wildberries|Юла|Smokershop|Яндекс Маркет'
 'Поездки и транспорт'='Авиасейлс|Авто.ру|Аэроэкспресс|ATI.SU|BlaBlaCar|Дром|Купибилет|Ozon Travel|Победа|Почта России|РЖД|Туту|Яндекс Карты'
 'Финансы'='Альфа-Банк|ВТБ Онлайн|Заём-расписка|Займ в долг срочно|Oplata.info|СберБанк Онлайн|Т-Банк|ЮMoney'
 'Работа и разработка'='1Т Старт|Adobe Acrobat|AnyDesk (пароль доступа)|Cloudflare|GitHub|HeadHunter|JetBrains|Контур.Толк|VMware Horizon|Wireshark Wiki|Zoom|VSThemes'
 'Учёба'='itProger|Mathprofi|SQL Academy|Яндекс Переводчик'
 'Почта и облако'='Apple ID|Gmail|Google|Google Drive|Huawei Cloud|iCloud|Mail.ru|Microsoft / Outlook / Xbox|Outlook|Рамблер Почта|Яндекс Почта|Яндекс ID'
 'Общение'='Discord|LinkedIn|MAX|Telegram|ВКонтакте|Одноклассники|TikTok'
 'Видео и музыка'='AnimeGO|Jut.su|Кинопоиск|Литрес|Premier|Rutube|Spotify|Twitch|VK Видео|YouTube|Яндекс Музыка'
 'Нейросети'='Алиса AI|Bing|ChatGPT|Claude|DeepSeek|GigaChat'
 'Связь и интернет'='Билайн|Happ|Karing|Kaspersky|МегаФон (личный кабинет)|МТС (личный кабинет)|OpenSpeedTest|Т2 / Tele2 (личный кабинет)|ZT'
 'Госуслуги'='Госуслуги|mos.ru'
}
$taskAssigned=0
foreach($taskTemplate in $taskData.Templates){
 $taskCategory='Другое'
 foreach($taskPair in $taskCategories.GetEnumerator()){if($taskPair.Value.Split('|') -contains $taskTemplate.Name){$taskCategory=$taskPair.Key;break}}
 $taskTemplate|Add-Member -NotePropertyName Category -NotePropertyValue $taskCategory -Force
 if($taskCategory -ne 'Другое'){$taskAssigned++}
}
$taskData.Version=5
[IO.File]::WriteAllText($taskPath,($taskData|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
Write-Output "Categorized $taskAssigned of $($taskData.Templates.Count) templates."

param([string]$Source)
$ErrorActionPreference='Stop'
$src=if($Source) { [IO.Path]::GetFullPath($Source) } else { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')) }
# A distinct worker URL prevents Chromium from reusing the previous release's
# executable service-worker cache after unpacked-extension refresh.
$browserManifest=Get-Content "$src\browser\manifest.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$workerName="background-v$($browserManifest.version).js"
Copy-Item -LiteralPath "$src\browser\background.js" -Destination "$src\browser\$workerName" -Force
$browserManifest.background.service_worker=$workerName
[IO.File]::WriteAllText("$src\browser\manifest.json",($browserManifest | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
$firefoxManifest=Get-Content "$src\browser\firefox-manifest.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$firefoxManifest.background.scripts=@($workerName)
[IO.File]::WriteAllText("$src\browser\firefox-manifest.json",($firefoxManifest | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
$files=[ordered]@{}
$mapping=[ordered]@{}
foreach($name in 'file-engine.zip','file-engine.json','winfsp.msi') { $mapping[$name]=Join-Path "$src\file-engine" $name }
foreach($name in 'WinUp.PasskeyEngine','BouncyCastle.Cryptography','CBOR','Numbers') { $mapping["$name.dll"]="$src\lib\$name.dll" }
$mapping['public-suffix-list.dat']="$src\public-suffix-list.dat"
$mapping['THIRD-PARTY.md']="$src\THIRD-PARTY.md"
foreach($file in Get-ChildItem "$src\browser" -File | Where-Object { $_.Extension -in '.json','.js','.html','.png' -or $_.Name -eq 'winup-firefox.xpi' }) { $mapping['browser/'+$file.Name]=$file.FullName }
foreach($file in Get-ChildItem "$src\licenses" -File) { $mapping['licenses/'+$file.Name]=$file.FullName }
foreach($name in $mapping.Keys) { $f=Get-Item -LiteralPath $mapping[$name]; $files[$name]=@{size=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName).Hash.ToLowerInvariant()} }
$psl=[regex]::Match([IO.File]::ReadAllText("$src\public-suffix-list.dat"),'(?m)^// VERSION: (.+)$').Groups[1].Value.Trim()
if(!$psl) { $psl='snapshot-'+(Get-FileHash "$src\public-suffix-list.dat").Hash.Substring(0,12) }
$versions=[ordered]@{}
$record=Get-Content "$src\updates\versions.json" -Raw -Encoding UTF8 | ConvertFrom-Json
foreach($property in $record.PSObject.Properties) { $versions[$property.Name]=$property.Value }
$versions['browser']=(Get-Content "$src\browser\manifest.json" -Raw -Encoding UTF8 | ConvertFrom-Json).version
$versions['psl']=$psl
$appVersion=[regex]::Match([IO.File]::ReadAllText("$src\Properties\AssemblyInfo.cs"),'AssemblyVersion\("([0-9.]+)"\)').Groups[1].Value
$v=[Version]$appVersion
$manifest=[ordered]@{schema=1;api=4;sequence=0;minApp="$($v.Major).$($v.Minor).$($v.Build).0";maxApp="$($v.Major).$($v.Minor).999.999";versions=$versions;files=$files}
[IO.File]::WriteAllText("$src\updates\components.json",($manifest | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))

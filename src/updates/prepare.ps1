param([string]$Source)
$ErrorActionPreference='Stop'
$src=if($Source) { [IO.Path]::GetFullPath($Source) } else { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')) }
$files=[ordered]@{}
$mapping=[ordered]@{}
foreach($name in 'file-engine.zip','file-engine.json','winfsp.msi') { $mapping[$name]=Join-Path "$src\file-engine" $name }
foreach($name in 'WinUp.PasskeyEngine','BouncyCastle.Cryptography','CBOR','Numbers') { $mapping["$name.dll"]="$src\lib\$name.dll" }
$mapping['public-suffix-list.dat']="$src\public-suffix-list.dat"
$mapping['THIRD-PARTY.md']="$src\THIRD-PARTY.md"
foreach($file in Get-ChildItem "$src\browser" -File | Where-Object { $_.Extension -in '.json','.js','.html','.png' }) { $mapping['browser/'+$file.Name]=$file.FullName }
foreach($file in Get-ChildItem "$src\licenses" -File) { $mapping['licenses/'+$file.Name]=$file.FullName }
foreach($name in $mapping.Keys) { $f=Get-Item -LiteralPath $mapping[$name]; $files[$name]=@{size=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName).Hash.ToLowerInvariant()} }
$psl=[regex]::Match([IO.File]::ReadAllText("$src\public-suffix-list.dat"),'(?m)^// VERSION: (.+)$').Groups[1].Value.Trim()
if(!$psl) { $psl='snapshot-'+(Get-FileHash "$src\public-suffix-list.dat").Hash.Substring(0,12) }
$versions=[ordered]@{}
$record=Get-Content "$src\updates\versions.json" -Raw | ConvertFrom-Json
foreach($property in $record.PSObject.Properties) { $versions[$property.Name]=$property.Value }
$versions['browser']=(Get-Content "$src\browser\manifest.json" -Raw | ConvertFrom-Json).version
$versions['psl']=$psl
$manifest=[ordered]@{schema=1;api=1;sequence=0;minApp='1.13.0.0';maxApp='1.13.999.999';versions=$versions;files=$files}
[IO.File]::WriteAllText("$src\updates\components.json",($manifest | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))

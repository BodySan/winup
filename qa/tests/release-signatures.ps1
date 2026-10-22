param([Parameter(Mandatory=$true)][string]$ReleaseDirectory,[string]$PreviousPublicKey)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Web.Extensions
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$exe=Join-Path $ReleaseDirectory 'WinUp.exe'
& (Join-Path $taskRoot 'tools\verify-app.ps1') -Path $exe
$assembly=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes($exe))
function ResourceText([string]$name){$reader=[IO.StreamReader]::new($assembly.GetManifestResourceStream($name));try{$reader.ReadToEnd()}finally{$reader.Dispose()}}
$public=ResourceText 'component-publisher.xml'
if($public -cne [IO.File]::ReadAllText((Join-Path $taskRoot 'src\updates\publisher.xml')) -or $public.Contains('<D>')){throw 'Embedded publisher key differs or contains private material'}
$rsa=[Security.Cryptography.RSACryptoServiceProvider]::new();$rsa.PersistKeyInCsp=$false
try{
 $rsa.FromXmlString($public)
 foreach($name in 'WinUp.exe','update.json'){
  $data=[IO.File]::ReadAllBytes((Join-Path $ReleaseDirectory $name))
  $signature=[IO.File]::ReadAllBytes((Join-Path $ReleaseDirectory ($name.Replace('update.json','update')+'.sig')))
  if(!$rsa.VerifyData($data,'SHA256',$signature)){throw ('Invalid signature: '+$name)}
  $data[$data.Length-1]=$data[$data.Length-1] -bxor 1
  if($rsa.VerifyData($data,'SHA256',$signature)){throw ('Changed payload accepted: '+$name)}
  $data[$data.Length-1]=$data[$data.Length-1] -bxor 1
  $signature[0]=$signature[0] -bxor 1
  if($rsa.VerifyData($data,'SHA256',$signature)){throw ('Changed signature accepted: '+$name)}
  Write-Output ('PASS signature and tamper rejection: '+$name)
 }
 $json=[Web.Script.Serialization.JavaScriptSerializer]::new()
 $baseline=$json.Deserialize((ResourceText 'components.json'),$assembly.GetType('WinUp.ComponentManifest'))
 $type=$assembly.GetType('WinUp.ComponentPackage')
 $flags=[Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
 $constructor=$type.GetConstructors($flags)|Where-Object {$_.GetParameters().Count -eq 4}|Select-Object -First 1
 if(!$constructor){throw 'Component package constructor missing'}
 $argsForPackage=[object[]]@([string](Join-Path $ReleaseDirectory 'components.wup'),[string]$public,$baseline.PSObject.BaseObject,[Version]$assembly.GetName().Version)
 $package=$constructor.Invoke($argsForPackage)
 try{
  $feed=Get-Content -LiteralPath (Join-Path $ReleaseDirectory 'update.json') -Raw|ConvertFrom-Json
  if($feed.sequence -ne $package.Manifest.sequence -or $feed.size -ne (Get-Item -LiteralPath $argsForPackage[0]).Length -or $feed.sha256 -ne (Get-FileHash -LiteralPath $argsForPackage[0]).Hash.ToLowerInvariant()){throw 'Feed does not describe inspected package'}
  if([DateTimeOffset]::Parse($feed.expiresUtc) -le [DateTimeOffset]::UtcNow){throw 'Feed has expired'}
  Write-Output ('PASS actual WinUp package inspection, all component hashes and feed binding: '+$feed.sequence)
 }finally{$package.Dispose()}
 if($PreviousPublicKey){
  $old=[IO.File]::ReadAllText($PreviousPublicKey)
  if($old -ceq $public){throw 'Publisher key did not change'}
  $argsForPackage[1]=$old;$rejected=$false
  try{$unexpected=$constructor.Invoke($argsForPackage);$unexpected.Dispose()}catch{if($_.Exception.ToString() -notmatch 'InvalidDataException|CryptographicException'){throw};$rejected=$true}
  if(!$rejected){throw 'Old publisher accepted the new package'}
  Write-Output 'PASS previous publisher key rejects new component package'
 }
 Write-Output 'PASS release signatures, embedded trust and component compatibility'
}finally{$rsa.Dispose()}

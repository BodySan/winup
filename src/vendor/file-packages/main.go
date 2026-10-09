// WinUp file packaging adapter. Cryptography is the unmodified age library.
// Passwords are received over inherited stdin; never arguments, environment or logs.
package main

import (
 "archive/tar"
 "bufio"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "time"
 "filippo.io/age"
 "golang.org/x/sys/windows"
)

type Item struct { Source string; Name string; Directory bool; Zone string }
type Request struct { Operation string; Password string; Input string; Output string; Items []Item }
type Record struct { Name string; Hash string; Size int64; Directory bool; Zone string }
type Manifest struct { Schema int; Records []Record }
const manifestName = ".winup-package.json"
func openHeldSource(path string) (*os.File,error) {
 full,e:=filepath.Abs(path);if e!=nil{return nil,e}
 if !strings.HasPrefix(full,`\\?\`) {if strings.HasPrefix(full,`\\`){full=`\\?\UNC\`+full[2:]}else{full=`\\?\`+full}}
 pointer,e:=windows.UTF16PtrFromString(full);if e!=nil{return nil,e}
 // The parent holds DELETE access when a verified move was requested.
 // Our read handle must share DELETE while the parent's own handle denies
 // third-party writes/deletes for the full operation.
 handle,e:=windows.CreateFile(pointer,windows.GENERIC_READ,windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,nil,windows.OPEN_EXISTING,windows.FILE_FLAG_OPEN_REPARSE_POINT,0)
 if e!=nil{return nil,e};return os.NewFile(uintptr(handle),path),nil
}

func validName(name string) bool {
 if name == "" || strings.HasPrefix(name,"/") || strings.ContainsAny(name,"\\:\x00") { return false }
 for _, p := range strings.Split(name,"/") {
  if p=="" || p=="." || p==".." || strings.TrimRight(p," .")!=p || strings.HasPrefix(strings.ToLower(p),".winup-") { return false }
  stem:=strings.ToUpper(strings.Split(p,".")[0])
  if stem=="CON" || stem=="PRN" || stem=="AUX" || stem=="NUL" || len(stem)==4 && (strings.HasPrefix(stem,"COM")||strings.HasPrefix(stem,"LPT")) && stem[3]>='0' && stem[3]<='9' {return false}
 }
 return true
}
func noLinks(path string) error {
 for p:=filepath.Clean(path);;p=filepath.Dir(p) {
  s,e:=os.Lstat(p);if e!=nil {return e};if s.Mode()&os.ModeSymlink!=0 {return errors.New("links_not_supported")}
  if filepath.Dir(p)==p {break}
 };return nil
}
func packageFile(r Request) (err error) {
 if len(r.Items)==0 || len(r.Items)>10000 {return errors.New("invalid_item_count")}
 recipient,e:=age.NewScryptRecipient(r.Password);if e!=nil{return e}
 out,e:=os.OpenFile(r.Output,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if e!=nil{return e}
 defer func(){out.Close();if err!=nil{os.Remove(r.Output)}}()
 encrypted,e:=age.Encrypt(out,recipient);if e!=nil{return e}
 archive:=tar.NewWriter(encrypted)
 m:=Manifest{Schema:1};seen:=map[string]bool{}
 for _,item:=range r.Items {
  if !validName(item.Name)||seen[strings.ToLower(item.Name)] {return errors.New("invalid_or_duplicate_name")};seen[strings.ToLower(item.Name)]=true
  if e=noLinks(item.Source);e!=nil{return e}
  s,e:=os.Stat(item.Source);if e!=nil{return e}
  if s.IsDir()!=item.Directory || !s.IsDir()&&!s.Mode().IsRegular(){return errors.New("source_changed")}
  header:=&tar.Header{Name:item.Name,Mode:0600,ModTime:s.ModTime(),Format:tar.FormatPAX}
  record:=Record{Name:item.Name,Directory:item.Directory,Zone:item.Zone}
  if item.Directory {header.Typeflag=tar.TypeDir;header.Mode=0700} else {header.Typeflag=tar.TypeReg;header.Size=s.Size();record.Size=s.Size()}
  if e=archive.WriteHeader(header);e!=nil{return e}
  if !item.Directory {
   input,e:=openHeldSource(item.Source);if e!=nil{return e};hash:=sha256.New()
   n,copyErr:=io.CopyN(io.MultiWriter(archive,hash),input,s.Size());input.Close()
   if copyErr!=nil||n!=s.Size(){return errors.New("source_read_failed")};record.Hash=hex.EncodeToString(hash.Sum(nil))
  }
  m.Records=append(m.Records,record)
 }
 metadata,e:=json.Marshal(m);if e!=nil{return e}
 if e=archive.WriteHeader(&tar.Header{Name:manifestName,Mode:0600,Size:int64(len(metadata)),ModTime:time.Now(),Typeflag:tar.TypeReg});e!=nil{return e}
 if _,e=archive.Write(metadata);e!=nil{return e};if e=archive.Close();e!=nil{return e};if e=encrypted.Close();e!=nil{return e}
 if e=out.Sync();e!=nil{return e};if e=out.Close();e!=nil{return e}
 // Read back the complete encrypted stream and compare every recorded content hash.
 _,e=unpack(Request{Input:r.Output,Password:r.Password},false);return e
}
func unpack(r Request, extract bool) (result Manifest,err error) {
 identity,e:=age.NewScryptIdentity(r.Password);if e!=nil{return result,e}
 // Bound maliciously expensive passphrase parameters without changing age defaults.
 identity.SetMaxWorkFactor(20)
 in,e:=os.Open(r.Input);if e!=nil{return result,e};defer in.Close()
 plaintext,e:=age.Decrypt(in,identity);if e!=nil{return result,errors.New("wrong_password_or_invalid_package")}
 if extract {if e=os.Mkdir(r.Output,0700);e!=nil{return result,e};defer func(){if err!=nil{os.RemoveAll(r.Output)}}()}
 archive:=tar.NewReader(plaintext);seen:=map[string]bool{};actual:=[]Record{};metadataSeen:=false;var total int64
 for {
  header,e:=archive.Next();if e==io.EOF{break};if e!=nil{return result,e}
  if metadataSeen {return result,errors.New("data_after_manifest")}
  if header.Name==manifestName {
   if header.Size>8*1024*1024||header.Typeflag!=tar.TypeReg{return result,errors.New("invalid_manifest")}
   if e=json.NewDecoder(io.LimitReader(archive,header.Size)).Decode(&result);e!=nil{return result,e};metadataSeen=true;continue
  }
  if !validName(header.Name)||seen[strings.ToLower(header.Name)]||len(actual)>=10000{return result,errors.New("invalid_or_duplicate_name")}
  seen[strings.ToLower(header.Name)]=true
  directory:=header.Typeflag==tar.TypeDir
  if !directory&&header.Typeflag!=tar.TypeReg{return result,errors.New("unsupported_archive_entry")}
  if header.Size<0||header.Size>1<<40||total>(1<<40)-header.Size{return result,errors.New("package_too_large")};total+=header.Size
  record:=Record{Name:header.Name,Directory:directory,Size:header.Size}
  var output *os.File
  if extract {
   target:=filepath.Join(r.Output,filepath.FromSlash(header.Name))
   if e=os.MkdirAll(filepath.Dir(target),0700);e!=nil{return result,e}
   if directory {if e=os.MkdirAll(target,0700);e!=nil{return result,e}} else {
    output,e=os.OpenFile(target,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if e!=nil{return result,e}
   }
  }
  if !directory {
   hash:=sha256.New();var writer io.Writer=hash;if output!=nil{writer=io.MultiWriter(output,hash)}
   n,copyErr:=io.Copy(writer,archive)
   if output!=nil{if syncErr:=output.Sync();copyErr==nil{copyErr=syncErr};output.Close()}
   if copyErr!=nil||n!=header.Size{return result,errors.New("corrupted_file")};record.Hash=hex.EncodeToString(hash.Sum(nil))
  }
  actual=append(actual,record)
 }
 // tar's EOF is before age's authentication trailer. Always drain and authenticate it.
 if _,e=io.Copy(io.Discard,plaintext);e!=nil{return result,e}
 if !metadataSeen||result.Schema!=1||len(result.Records)!=len(actual){return result,errors.New("missing_or_invalid_manifest")}
 for i,record:=range result.Records {
  a:=actual[i];if record.Name!=a.Name||record.Directory!=a.Directory||record.Size!=a.Size||record.Hash!=a.Hash{return result,errors.New("content_verification_failed")}
  if record.Zone!="" {
   zone,e:=base64.StdEncoding.DecodeString(record.Zone);if e!=nil||len(zone)>65536||record.Directory{return result,errors.New("invalid_download_metadata")}
   if extract {
    target:=filepath.Join(r.Output,filepath.FromSlash(record.Name))+":Zone.Identifier"
    if e=os.WriteFile(target,zone,0600);e!=nil{return result,errors.New("cannot_restore_download_metadata")}
    check,e:=os.ReadFile(target);if e!=nil||string(check)!=string(zone){return result,errors.New("download_metadata_verification_failed")}
   }
  }
 };return result,nil
}
func main() {
 // This helper serves one command. Limit protocol size and emit no request contents.
 input:=bufio.NewReader(io.LimitReader(os.Stdin,12*1024*1024));var r Request
 // Framework's redirected stdin may emit its UTF-8 preamble before our writer.
 if prefix,e:=input.Peek(3);e==nil&&string(prefix)=="\xef\xbb\xbf" {input.Discard(3)}
 err:=json.NewDecoder(input).Decode(&r)
 if err==nil&&len(r.Password)<1 {err=errors.New("password_required")}
 if err==nil {
  switch r.Operation {case "pack":err=packageFile(r);case "unpack":_,err=unpack(r,true);case "verify":_,err=unpack(r,false);default:err=errors.New("unknown_operation")}
 }
 r.Password="";if err!=nil{json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":false,"error":fmt.Sprint(err)});os.Exit(1)}
 json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":true})
}

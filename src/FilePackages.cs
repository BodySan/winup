using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace WinUp {
    // Portable tar.age packages. The age helper never receives secrets in arguments.
    internal static class FilePackages {
        internal static string PackageOutputName(string path){return path.EndsWith(".age",StringComparison.OrdinalIgnoreCase)?path:path.EndsWith(".tar",StringComparison.OrdinalIgnoreCase)?path+".age":path+".tar.age";}
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
        internal static void WriteZone(string path,byte[] bytes) {
            using(var handle=CreateFileW(SafePaths.Native(path)+":Zone.Identifier",0x40000000u,1,IntPtr.Zero,2,0x00200000u,IntPtr.Zero)) {
                if(handle.IsInvalid)throw new IOException("Не удалось сохранить отметку загрузки.");
                using(var stream=new FileStream(handle,FileAccess.Write)){stream.Write(bytes,0,bytes.Length);stream.Flush(true);}
            }
            if(!bytes.SequenceEqual(ReadZone(path)))throw new IOException("Отметка загрузки не прошла проверку.");
        }
        internal static byte[] ReadZone(string path){using(var handle=CreateFileW(SafePaths.Native(path)+":Zone.Identifier",0x80000000u,1,IntPtr.Zero,3,0x00200000u,IntPtr.Zero)){
            if(handle.IsInvalid)throw new IOException("Не удалось прочитать отметку загрузки.");using(var stream=new FileStream(handle,FileAccess.Read))using(var buffer=new MemoryStream()){stream.CopyTo(buffer);return buffer.ToArray();}}}
        internal static void Pack(string[] sources,string output,string password,bool move,CancellationToken cancel,Func<string,string> zoneLookup=null) {
            output=Path.GetFullPath(output); SafePaths.NoReparseParents(output);
            if(File.Exists(output) || Directory.Exists(output)) throw new IOException("Выберите новое имя пакета: существующие данные не заменяются.");
            var leases=new List<SourceLease>(); var items=new List<object>();
            var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string stage=Path.Combine(Path.GetDirectoryName(output),".winup-package-"+Guid.NewGuid().ToString("N"));
            using(var destination=SourceLease.HoldDirectories(Path.GetDirectoryName(output))) try {
                foreach(string sourceName in sources) {
                    cancel.ThrowIfCancellationRequested(); string source=Path.GetFullPath(sourceName);
                    if(SafePaths.IsWithin(output,source)) throw new IOException("Пакет нельзя сохранять внутри упаковываемой папки.");
                    var lease=SourceLease.Acquire(source,move); leases.Add(lease);
                    string rootName=Path.GetFileName(source.TrimEnd('\\'));
                    foreach(string relative in lease.Snapshot) {
                        string name=(rootName+(relative.Length==0 ? "" : "/"+relative.Replace('\\','/')));
                        if(!names.Add(name)) throw new IOException("Совпали имена выбранных файлов. Упакуйте их отдельно или выберите общую родительскую папку.");
                        string path=relative.Length==0 ? source : SafePaths.Child(source,relative);
                        items.Add(new {Source=path,Name=name,Directory=Directory.Exists(SafePaths.Native(path)),Zone=lease.ZoneFor(relative)??(zoneLookup==null ? null : zoneLookup(path))});
                    }
                }
                Run(new {Operation="pack",Password=password,Output=stage,Items=items},cancel);
                cancel.ThrowIfCancellationRequested(); File.Move(SafePaths.Native(stage),SafePaths.Native(output));
                // Helper read-back verification completed before originals can be removed.
                if(move) foreach(var lease in leases) lease.DeleteVerifiedOriginals();
            } finally { if(File.Exists(SafePaths.Native(stage))) File.Delete(SafePaths.Native(stage)); foreach(var lease in leases) lease.Dispose(); }
        }
        internal static void Unpack(string input,string output,string password,CancellationToken cancel) {
            input=Path.GetFullPath(input); output=Path.GetFullPath(output);
            SafePaths.NoReparseParents(output);
            if(Directory.Exists(output) || File.Exists(output)) throw new IOException("Выберите новую папку: существующие данные не заменяются.");
            string stage=Path.Combine(Path.GetDirectoryName(output),".winup-unpack-"+Guid.NewGuid().ToString("N"));
            using(var source=SourceLease.Acquire(input,false))
            using(var destination=SourceLease.HoldDirectories(Path.GetDirectoryName(output))) try {
                Run(new {Operation="unpack",Password=password,Input=input,Output=stage},cancel);
                cancel.ThrowIfCancellationRequested(); Directory.Move(SafePaths.Native(stage),SafePaths.Native(output));
            } finally { RemoveOwnedStage(stage,Path.GetDirectoryName(output)); }
        }
        internal static void Verify(string input,string password,CancellationToken cancel) {
            using(var source=SourceLease.Acquire(input,false)) Run(new {Operation="verify",Input=Path.GetFullPath(input),Password=password},cancel);
        }
        static void Run(object request,CancellationToken cancel) {
            var locks=new List<FileStream>(); SourceLease directories=null;string json=null;
            try {
                cancel.ThrowIfCancellationRequested(); string runtime=FileVaultClient.ExtractRuntime(locks,out directories);
                var info=new ProcessStartInfo(Path.Combine(runtime,"WinUpPackages.exe")) {UseShellExecute=false,CreateNoWindow=true,
                    RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,WorkingDirectory=runtime};
                using(var process=Process.Start(info)) {
                    try {
                    process.ErrorDataReceived+=delegate{}; process.BeginErrorReadLine();
                    using(cancel.Register(delegate { try {process.Kill();}catch{} })) {
                        json=new JavaScriptSerializer {MaxJsonLength=12*1024*1024}.Serialize(request);
                        using(var writer=new StreamWriter(process.StandardInput.BaseStream,new UTF8Encoding(false))){writer.WriteLine(json);}
                        string response=process.StandardOutput.ReadLine(); process.WaitForExit(); cancel.ThrowIfCancellationRequested();
                        var result=response==null ? null : new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(response);
                        if(process.ExitCode!=0 || result==null || !result.ContainsKey("ok") || !(bool)result["ok"])
                            throw new IOException("Пакет не создан или не открыт. Проверьте пароль, свободное место и доступ к файлам. "+
                                (result!=null && result.ContainsKey("error") ? result["error"] : "Модуль завершил работу."));
                    }
                    }finally {if(!process.HasExited){try{process.Kill();process.WaitForExit(5000);}catch{}}}
                }
            }finally {Secure.Wipe(json);foreach(var handle in locks)handle.Dispose();if(directories!=null)directories.Dispose();}
        }
        internal static void RemoveOwnedStage(string stage,string parent) {
            if(!Directory.Exists(SafePaths.Native(stage)))return;
            if(!SafePaths.IsWithin(stage,parent) || Path.GetDirectoryName(stage)!=Path.GetFullPath(parent) || !Path.GetFileName(stage).StartsWith(".winup-"))
                throw new IOException("Неверный путь временной операции.");
            SafePaths.NoReparseParents(stage);
            foreach(string path in Directory.GetFileSystemEntries(SafePaths.Native(stage),"*",SearchOption.AllDirectories)) SafePaths.NoReparseParents(SafePaths.Ordinary(path));
            Directory.Delete(SafePaths.Native(stage),true);
        }
        // Ciphertext-only snapshot. Close the vault before calling this operation.
        internal static void BackupVault(string source,string output,CancellationToken cancel) {
            source=Path.GetFullPath(source);output=Path.GetFullPath(output);SafePaths.NoReparseParents(output);
            if(SafePaths.IsWithin(output,source)||SafePaths.IsWithin(source,output))throw new IOException("Резерв должен находиться за пределами хранилища.");
            if(Directory.Exists(output)||File.Exists(output))throw new IOException("Выберите новое имя папки резервной копии.");
            string stage=Path.Combine(Path.GetDirectoryName(output),".winup-backup-"+Guid.NewGuid().ToString("N"));
            using(var lease=SourceLease.Acquire(source,false))
            using(var destination=SourceLease.HoldDirectories(Path.GetDirectoryName(output))) try {
                Directory.CreateDirectory(stage);
                var hashes=new Dictionary<string,string>();
                foreach(string relative in lease.Snapshot) {
                    cancel.ThrowIfCancellationRequested(); if(relative.Length==0 || relative.Equals("winup-backup.json",StringComparison.OrdinalIgnoreCase))continue;
                    string src=SafePaths.Child(source,relative), dst=SafePaths.Child(stage,relative);
                    if(Directory.Exists(SafePaths.Native(src))){Directory.CreateDirectory(SafePaths.Native(dst));continue;}
                    using(var input=File.OpenRead(SafePaths.Native(src)))using(var target=new FileStream(SafePaths.Native(dst),FileMode.CreateNew,FileAccess.Write,FileShare.None)) {input.CopyTo(target);target.Flush(true);}
                    string hash=Hash(src);if(hash!=Hash(dst))throw new IOException("Проверка резервной копии не пройдена.");hashes[relative]=hash;
                }
                if(!File.Exists(Path.Combine(stage,"masterkey.cryptomator"))||!File.Exists(Path.Combine(stage,"vault.cryptomator")))throw new IOException("Выбрана папка без файлового хранилища.");
                File.WriteAllText(Path.Combine(stage,"winup-backup.json"),new JavaScriptSerializer {MaxJsonLength=12*1024*1024}.Serialize(new {schema=1,created=DateTime.UtcNow.ToString("o"),files=hashes}));
                cancel.ThrowIfCancellationRequested();Directory.Move(SafePaths.Native(stage),SafePaths.Native(output));
            }finally {RemoveOwnedStage(stage,Path.GetDirectoryName(output));}
        }
        internal static void VerifyBackup(string folder,CancellationToken cancel) {
            using(var lease=SourceLease.Acquire(folder,false)) {
                string json=File.ReadAllText(Path.Combine(folder,"winup-backup.json"));
                var manifest=new JavaScriptSerializer {MaxJsonLength=12*1024*1024}.Deserialize<BackupManifest>(json);
                if(manifest==null||manifest.schema!=1||manifest.files==null||manifest.files.Count>10000)throw new IOException("Неверный список резервной копии.");
                foreach(var pair in manifest.files){cancel.ThrowIfCancellationRequested();if(Hash(SafePaths.Child(folder,pair.Key))!=pair.Value)throw new IOException("Резерв повреждён: "+pair.Key);}
                var actual=lease.Snapshot.Where(x=>x.Length>0&&!Directory.Exists(SafePaths.Native(SafePaths.Child(folder,x)))&&!x.Equals("winup-backup.json",StringComparison.OrdinalIgnoreCase));
                if(!new HashSet<string>(actual,StringComparer.OrdinalIgnoreCase).SetEquals(manifest.files.Keys))throw new IOException("Состав резервной копии изменился.");
            }
        }
        sealed class BackupManifest {public int schema{get;set;}public Dictionary<string,string> files{get;set;}}
        static string Hash(string path){using(var input=File.OpenRead(SafePaths.Native(path)))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    }
}

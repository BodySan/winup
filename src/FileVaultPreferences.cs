using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace WinUp {
    internal sealed class FileVaultPreferences {
        public string Drive{get;set;}
        public bool ReadOnly{get;set;}
        public bool History{get;set;}
        public int HistoryMiB{get;set;}
        public int HistoryKeep{get;set;}
        public bool AutoBackup{get;set;}
        public string BackupFolder{get;set;}
        public string Editor{get;set;}
        public bool ProjectMode{get;set;}
        public int ProjectIdleMinutes{get;set;}
        public FileVaultPreferences(){Drive="";History=true;HistoryMiB=1024;HistoryKeep=10;BackupFolder="";Editor="";ProjectIdleMinutes=120;}
        static string PathFor(string vault) {
            string hash;using(var sha=SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(Path.GetFullPath(vault).ToUpperInvariant()))).Replace("-","");
            return Path.Combine(Paths.Data,"file-preferences",hash+".json");
        }
        internal static FileVaultPreferences Load(string vault) {
            string path=PathFor(vault);if(!File.Exists(path))return new FileVaultPreferences();
            SafePaths.NoReparseParents(path);
            if(new FileInfo(path).Length>65536)throw new IOException("Повреждены настройки хранилища.");
            var p=new JavaScriptSerializer().Deserialize<FileVaultPreferences>(File.ReadAllText(path));if(p==null)throw new IOException("Неверные настройки хранилища.");
            p.Validate();return p;
        }
        internal void Validate(){
            HistoryMiB=Math.Max(16,Math.Min(102400,HistoryMiB));HistoryKeep=Math.Max(1,Math.Min(100,HistoryKeep));
            ProjectIdleMinutes=Math.Max(1,Math.Min(1440,ProjectIdleMinutes));
            if(Drive!=""&&(Drive==null||Drive.Length!=3||Drive[0]<'D'||Drive[0]>'Z'||Drive.Substring(1)!=":\\"))Drive="";
            BackupFolder=BackupFolder??"";Editor=Editor??"";
            if(BackupFolder!=""&&!Path.IsPathRooted(BackupFolder))throw new IOException("Нужен полный путь к резервной папке.");
            if(Editor!=""&&(!Path.IsPathRooted(Editor)||!File.Exists(Editor)||!Editor.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)))throw new IOException("Выберите существующий EXE редактора.");
        }
        internal void Save(string vault){
            Validate();string path=PathFor(vault);SafePaths.NoReparseParents(path);Directory.CreateDirectory(Path.GetDirectoryName(path));
            string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
            using(var held=SourceLease.HoldDirectories(Path.GetDirectoryName(path)))try {
                File.WriteAllText(temp,new JavaScriptSerializer().Serialize(this));
                if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
            }finally{if(File.Exists(temp))File.Delete(temp);}
        }
    }
}

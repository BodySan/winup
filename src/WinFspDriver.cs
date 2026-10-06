using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Text.RegularExpressions;

namespace WinUp {
    internal static class WinFspDriver {
        public static string InstalledVersion {
            get {
                try {
                    using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry32))
                    using(var key=root.OpenSubKey(@"SOFTWARE\WinFsp")) {
                        string folder=key==null ? null : key.GetValue("InstallDir") as string;
                        string path=folder==null ? null : Path.Combine(folder,"bin","winfsp-x64.dll");
                        return path!=null && File.Exists(path) ? FileVersionInfo.GetVersionInfo(path).FileVersion : "не установлен";
                    }
                } catch { return "не удалось определить"; }
            }
        }
        public static bool Installed {
            get {
                using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry32))
                using(var key=root.OpenSubKey(@"SOFTWARE\WinFsp")) {
                    string folder=key==null ? null : key.GetValue("InstallDir") as string;
                    return folder!=null && File.Exists(Path.Combine(folder,"bin","winfsp-x64.dll"));
                }
            }
        }
        public static bool Install() {
            string folder=Path.Combine(Paths.Data,"driver-installer");
            SafePaths.NoReparseParents(folder); Directory.CreateDirectory(folder);
            string path=Path.Combine(folder,"winfsp.msi"); SafePaths.NoReparseParents(path);
            using(var input=ComponentResources.Open("winfsp.msi"))
            using(var output=new FileStream(path,FileMode.Create,FileAccess.Write,FileShare.None)) input.CopyTo(output);
            using(var held=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                using(var sha=SHA256.Create()) if(BitConverter.ToString(sha.ComputeHash(held)).Replace("-","").ToLowerInvariant()!=ComponentResources.Current.files["winfsp.msi"].sha256)
                    throw new IOException("Установочный файл WinFsp повреждён.");
                if(!Signature.SignedByName(path,"NAVIMATICS LLC")) throw new IOException("Подпись установочного файла WinFsp не прошла проверку.");
                var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"msiexec.exe")) {
                    Arguments="/i \""+path+"\" /qn /norestart",UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden };
                using(var process=Process.Start(start)) {
                    process.WaitForExit();
                    if(process.ExitCode==3010) throw new IOException("WinFsp установлен. Для подключения диска перезапустите Windows.");
                    if(process.ExitCode!=0) throw new IOException("Установка WinFsp завершилась с кодом "+process.ExitCode+".");
                }
            }
            return Installed;
        }
        internal static string UpdateOfficial(CancellationToken cancellation) {
            var release=ComponentPackage.Json().Deserialize<Dictionary<string,object>>(ComponentInventory.Get("https://api.github.com/repos/winfsp/winfsp/releases/latest"));
            var assets=((IEnumerable)release["assets"]).Cast<Dictionary<string,object>>();
            var asset=assets.FirstOrDefault(a=>Regex.IsMatch(Convert.ToString(a["name"]),@"\Awinfsp-2\.\d+(?:\.\d+)?\.msi\z",RegexOptions.IgnoreCase));
            if(asset==null) throw new IOException("Нет совместимого официального WinFsp 2.x. Нужна новая версия WinUp.");
            string name=Convert.ToString(asset["name"]), version=Regex.Match(name,@"\d+(?:\.\d+)+").Value;
            if(!ComponentInventory.Newer(InstalledVersion,version)) return "Установленный WinFsp не старее официального выпуска "+version+".";
            string folder=Path.Combine(Paths.Data,"driver-installer"); SafePaths.NoReparseParents(folder); Directory.CreateDirectory(folder);
            string path=Path.Combine(folder,Guid.NewGuid().ToString("N")+".msi");
            try {
                using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                    ComponentNetwork.Download(Convert.ToString(asset["browser_download_url"]),output,32L*1024*1024,cancellation); output.Flush(true);
                }
                using(var held=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                    if(!Signature.SignedByName(path,"NAVIMATICS LLC")) throw new IOException("Подпись официального WinFsp не прошла проверку.");
                    cancellation.ThrowIfCancellationRequested();
                    var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"msiexec.exe")) {
                        Arguments="/i \""+path+"\" /qn /norestart",UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden };
                    using(var process=Process.Start(start)) {
                        process.WaitForExit();
                        if(process.ExitCode==3010) return "WinFsp обновлён. Перезапустите Windows для применения драйвера.";
                        if(process.ExitCode!=0) throw new IOException("Обновление WinFsp завершилось с кодом "+process.ExitCode+".");
                    }
                }
                return "WinFsp обновлён: "+InstalledVersion+".";
            } finally { if(File.Exists(path)) File.Delete(path); }
        }
    }
}

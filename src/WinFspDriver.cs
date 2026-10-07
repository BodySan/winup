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
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace WinUp {
    internal static class WinFspDriver {
        [StructLayout(LayoutKind.Sequential)] struct DriverStatus {public uint type,state,controls,win32Exit,specificExit,checkpoint,waitHint;}
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceStatus(IntPtr service,out DriverStatus status);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool StartService(IntPtr service,uint count,IntPtr args);
        [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr service);
        internal static void EnsureRunning() {
            string installed;
            using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry32))
            using(var key=root.OpenSubKey(@"SOFTWARE\WinFsp"))installed=key==null ? null : key.GetValue("InstallDir") as string;
            if(string.IsNullOrEmpty(installed))throw new IOException("WinFsp не установлен. Установите его кнопкой во вкладке «Файлы».");
            string prefix=Path.GetFullPath(installed).TrimEnd('\\')+"\\",name=null;
            using(var services=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services")) {
                foreach(string candidate in services.GetSubKeyNames().Where(x=>x=="WinFsp" || Regex.IsMatch(x,@"\AWinFsp\+\d{8}T\d{6}Z\z")).OrderByDescending(x=>x,StringComparer.Ordinal)) {
                    using(var key=services.OpenSubKey(candidate)) {
                        string image=Convert.ToString(key.GetValue("ImagePath")).Trim('"');
                        if(image.StartsWith(@"\??\",StringComparison.Ordinal))image=image.Substring(4);
                        if(!image.StartsWith(prefix,StringComparison.OrdinalIgnoreCase) || !image.EndsWith("\\winfsp-x64.sys",StringComparison.OrdinalIgnoreCase) || !File.Exists(image))continue;
                        name=candidate;break;
                    }
                }
            }
            if(name==null)throw new IOException("Файлы WinFsp есть, но драйвер не зарегистрирован. Переустановите WinFsp официальной кнопкой и перезапустите Windows.");
            IntPtr manager=OpenSCManager(null,null,1),service=IntPtr.Zero;
            try {
                if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
                service=OpenService(manager,name,0x14);
                if(service==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
                DriverStatus status;
                if(!QueryServiceStatus(service,out status))throw new Win32Exception(Marshal.GetLastWin32Error());
                if(status.state==4)return;
                if(!StartService(service,0,IntPtr.Zero) && Marshal.GetLastWin32Error()!=1056)throw new Win32Exception(Marshal.GetLastWin32Error());
                for(int i=0;i<40;i++) {
                    if(QueryServiceStatus(service,out status) && status.state==4)return;
                    Thread.Sleep(50);
                }
                throw new IOException("Драйвер WinFsp не запустился вовремя. Перезапустите Windows и повторите подключение диска.");
            }catch(Win32Exception e){throw new IOException("Не удалось запустить установленный драйвер WinFsp: "+e.Message+". Перезапустите Windows; если не поможет, переустановите WinFsp официальной кнопкой.",e);}
            finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);if(manager!=IntPtr.Zero)CloseServiceHandle(manager);}
        }
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
            string path=Path.Combine(folder,Guid.NewGuid().ToString("N")+".msi"); SafePaths.NoReparseParents(path);
            using(var directoryLease=SourceLease.HoldDirectories(folder)) {
            try {
            using(var input=ComponentResources.Open("winfsp.msi"))
            using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {input.CopyTo(output);output.Flush(true);}
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
            } finally {if(File.Exists(path))File.Delete(path);}
            }
            return Installed;
        }
        internal static string UpdateOfficial(CancellationToken cancellation) {
            var release=ComponentPackage.Json().Deserialize<Dictionary<string,object>>(ComponentInventory.Get("https://api.github.com/repos/winfsp/winfsp/releases/latest",cancellation:cancellation));
            var assets=((IEnumerable)release["assets"]).Cast<Dictionary<string,object>>();
            var asset=assets.FirstOrDefault(a=>Regex.IsMatch(Convert.ToString(a["name"]),@"\Awinfsp-2\.\d+(?:\.\d+)?\.msi\z",RegexOptions.IgnoreCase));
            if(asset==null) throw new IOException("Нет совместимого официального WinFsp 2.x. Нужна новая версия WinUp.");
            string name=Convert.ToString(asset["name"]), version=Regex.Match(name,@"\d+(?:\.\d+)+").Value;
            if(!ComponentInventory.Newer(InstalledVersion,version)) return "Установленный WinFsp не старее официального выпуска "+version+".";
            string folder=Path.Combine(Paths.Data,"driver-installer"); SafePaths.NoReparseParents(folder); Directory.CreateDirectory(folder);
            string path=Path.Combine(folder,Guid.NewGuid().ToString("N")+".msi");
            using(var directoryLease=SourceLease.HoldDirectories(folder)) {
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
}

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace WinUp {
    // A window title is a search hint, never evidence of who will receive input.
    // Only the selected executable or an exact packaged app identity may match.
    internal sealed class DesktopTarget {
        readonly string executable, appId;
        DesktopTarget(string executable,string appId) { this.executable=executable;this.appId=appId; }
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]
        static extern int GetApplicationUserModelId(IntPtr process,ref uint length,StringBuilder value);

        [ComImport,Guid("000214F9-0000-0000-C000-000000000046"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IShellLinkW {
            void GetPath([Out,MarshalAs(UnmanagedType.LPWStr)] StringBuilder path,int capacity,IntPtr findData,uint flags);
        }
        static string ShortcutExecutable(string shortcut) {
            object link=null;
            try {
                link=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("00021401-0000-0000-C000-000000000046")));
                ((IPersistFile)link).Load(shortcut,0); // STGM_READ; no Resolve, launch or repair.
                var target=new StringBuilder(32768);
                ((IShellLinkW)link).GetPath(target,target.Capacity,IntPtr.Zero,4); // SLGP_RAWPATH.
                return target.ToString();
            } finally { if(link!=null && Marshal.IsComObject(link)) Marshal.FinalReleaseComObject(link); }
        }
        internal static DesktopTarget Create(string target,out string reason) {
            reason=null;
            try {
                if(string.IsNullOrWhiteSpace(target)) { reason="Для безопасного ввода выберите путь к приложению.";return null; }
                if(LocalApplications.IsShell(target)) {
                    string id=target.Substring(LocalApplications.ShellPrefix.Length);
                    if(id.Length==0 || id.Length>512 || id.IndexOfAny(new[] {'\r','\n','\0','"','<','>','|','?','*'})>=0 || id.Contains("://")) {
                        reason="Некорректный идентификатор приложения Windows.";return null;
                    }
                    return new DesktopTarget(null,id);
                }
                string path=Path.GetFullPath(Paths.Full(target));
                if(!File.Exists(path)) {reason="Выбранное приложение не найдено на этом ПК.";return null;}
                if(Path.GetExtension(path).Equals(".lnk",StringComparison.OrdinalIgnoreCase)) {
                    string resolved=ShortcutExecutable(path);
                    if(string.IsNullOrWhiteSpace(resolved)) {reason="Ярлык не содержит проверяемого пути к программе. Выберите её файл .exe.";return null;}
                    path=Path.GetFullPath(Paths.Full(resolved));
                }
                if(!Path.GetExtension(path).Equals(".exe",StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) {
                    reason="Для автозаполнения нужен существующий .exe или ярлык на него. Выберите исполняемый файл приложения.";return null;
                }
                return new DesktopTarget(path,null);
            } catch {
                reason="Не удалось проверить путь приложения. Выберите его исполняемый файл .exe; ввод отменён.";return null;
            }
        }
        static string PackageIdentity(int pid) {
            var handle=OpenProcess(0x1000,false,pid); // PROCESS_QUERY_LIMITED_INFORMATION.
            if(handle==IntPtr.Zero) return null;
            try {
                uint length=0;
                if(GetApplicationUserModelId(handle,ref length,null)!=122 || length<2 || length>1024) return null;
                var id=new StringBuilder((int)length);
                return GetApplicationUserModelId(handle,ref length,id)==0 ? id.ToString() : null;
            } catch {return null;} finally {CloseHandle(handle);}
        }
        internal bool Matches(IntPtr window) { string reason;return Verify(window,out reason); }
        internal bool Verify(IntPtr window,out string reason) {
            reason=null;
            if(window==IntPtr.Zero || !Win.IsWindow(window)) {reason="Окно приложения закрыто.";return false;}
            uint pid;
            if(GetWindowThreadProcessId(window,out pid)==0 || pid==0) {reason="Не удалось определить программу окна; ввод отменён.";return false;}
            var before=Proc.Identity((int)pid);
            if(before==null) {reason="Не удалось проверить процесс окна; ввод отменён.";return false;}
            bool matches=appId!=null ? string.Equals(PackageIdentity((int)pid),appId,StringComparison.Ordinal) : Proc.SameFile(before.Path,executable);
            uint afterPid;var after=Proc.Identity((int)pid);
            if(!matches || !Win.IsWindow(window) || GetWindowThreadProcessId(window,out afterPid)==0 || afterPid!=pid || after==null || after.Started!=before.Started) {
                reason=appId!=null ? "Принадлежность окна выбранному приложению Windows не подтверждена. Выберите его .exe либо войдите вручную; автозаполнение остановлено." :
                    "Окно принадлежит другой программе или процесс сменился; автозаполнение остановлено.";
                return false;
            }
            return true;
        }
    }
}

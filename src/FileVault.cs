using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

namespace WinUp
{
    // All cryptography and file formats are provided by unchanged Cryptomator libraries.
    // The private helper has no UI, network listener or command-line password.
    internal sealed class FileVaultClient : IDisposable
    {
        Process process;
        int disposed;
        readonly object sync = new object();
        readonly List<FileStream> runtimeLocks = new List<FileStream>();
        SourceLease runtimeDirectories;
        public string Folder { get; private set; }
        public string MountPoint { get; private set; }
        public bool Open { get { var p=process; try { return p != null && !p.HasExited; } catch { return false; } } }

        public FileVaultClient(string folder, string password, bool create, CancellationToken cancellation = default(CancellationToken))
        {
            Folder = Path.GetFullPath(folder);
            SafePaths.NoReparseParents(Folder);
            try
            {
                string root = ExtractRuntime(runtimeLocks,out runtimeDirectories);
                cancellation.ThrowIfCancellationRequested();
                var info = new ProcessStartInfo(Path.Combine(root, "WinUpFiles.exe")) {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
                    WorkingDirectory = root };
                process = Process.Start(info);
                process.ErrorDataReceived += delegate { }; // never persist paths or secrets from diagnostics
                process.BeginErrorReadLine();
                using (cancellation.Register(Cancel)) Call(create ? "create" : "open", Folder, password);
            }
            catch { Dispose(); throw; }
        }

        static string ExtractRuntime(List<FileStream> held,out SourceLease directories)
        {
            var asm = Assembly.GetExecutingAssembly();
            Dictionary<string, string> hashes;
            using (var reader = new StreamReader(ComponentResources.Open("file-engine.json")))
                hashes = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 }.Deserialize<Dictionary<string, string>>(reader.ReadToEnd());
            string root = Path.Combine(Paths.Data, "file-engines", ComponentResources.RuntimeId);
            SafePaths.NoReparseParents(root);
            Directory.CreateDirectory(root);
            directories=SourceLease.HoldDirectories(root);
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(root).SetAccessControl(security);
            using (var zip = new ZipArchive(ComponentResources.Open("file-engine.zip"), ZipArchiveMode.Read))
            {
                foreach (var pair in hashes)
                {
                    string path = SafePaths.Child(root, pair.Key);
                    SafePaths.NoReparseParents(path);
                    bool valid = false;
                    if (File.Exists(path)) using (var input = File.OpenRead(path)) using (var sha = SHA256.Create())
                        valid = Hex(sha.ComputeHash(input)) == pair.Value;
                    if (!valid)
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(path));
                        var entry = zip.GetEntry(pair.Key);
                        if (entry == null) throw new IOException("Повреждён встроенный модуль файлового хранилища.");
                        using (var input = entry.Open()) using (var output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None)) input.CopyTo(output);
                    }
                    var handle = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    held.Add(handle);
                    using (var sha = SHA256.Create()) if (Hex(sha.ComputeHash(handle)) != pair.Value)
                        throw new IOException("Проверка файлового модуля не пройдена.");
                }
            }
            // Extra DLL/JAR/config files must never become loadable by the helper.
            var pending = new Stack<string>(); pending.Push(root);
            while(pending.Count>0)
            {
                string directory=pending.Pop(); SafePaths.NoReparseParents(directory);
                foreach(string child in Directory.GetDirectories(directory)) { SafePaths.NoReparseParents(child); pending.Push(child); }
                foreach(string path in Directory.GetFiles(directory)) {
                    SafePaths.NoReparseParents(path);
                    string relative = path.Substring(root.Length + 1).Replace('\\','/');
                    if (!hashes.ContainsKey(relative)) throw new IOException("В папке файлового модуля обнаружен посторонний файл.");
                }
            }
            return root;
        }
        static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }
        internal Dictionary<string, object> Call(string command, params string[] fields)
        {
            lock (sync)
            {
                if (!Open) throw new IOException("Файловое хранилище закрыто.");
                var encoded = new List<string>();
                string line = null;
                try
                {
                    foreach (string field in fields)
                    {
                        byte[] bytes = Encoding.UTF8.GetBytes(field ?? "");
                        try { encoded.Add(Convert.ToBase64String(bytes)); }
                        finally { Array.Clear(bytes,0,bytes.Length); }
                    }
                    line = command + "\t" + string.Join("\t", encoded);
                    process.StandardInput.WriteLine(line); process.StandardInput.Flush();
                    string response=null; int diagnostics=0;
                    for(int i=0;i<32;i++) {
                        string received=process.StandardOutput.ReadLine();
                        if(received==null || received.Length>4*1024*1024) break;
                        int marker=received.IndexOf("WUP2\t",StringComparison.Ordinal);
                        if(marker>=0) { response=received.Substring(marker+5); break; }
                        diagnostics+=received.Length; if(diagnostics>65536) break;
                    }
                    if(response==null) throw new IOException("Файловый модуль завершил работу или нарушил протокол.");
                    var result = new JavaScriptSerializer { MaxJsonLength = 4 * 1024 * 1024 }.Deserialize<Dictionary<string,object>>(response);
                    if (result == null || !result.ContainsKey("ok") || !(bool)result["ok"])
                        throw new IOException("Операция не выполнена: " + (result != null && result.ContainsKey("error") ? result["error"] : "сбой модуля") +
                            (result != null && result.ContainsKey("detail") ? " — " + result["detail"] : ""));
                    return result;
                }
                finally { Secure.Wipe(line); foreach (string field in encoded) Secure.Wipe(field); }
            }
        }
        public void Import(string source, string destination, bool move)
        {
            using (var lease = SourceLease.Acquire(source, move))
            {
                SafePaths.NoReparseParents(Folder);
                if (SafePaths.IsWithin(source, Folder) || SafePaths.IsWithin(Folder, source) ||
                    MountPoint != null && SafePaths.IsWithin(source, MountPoint))
                    throw new IOException("Исходник и файловое хранилище не должны находиться друг внутри друга.");
                Call("import", Path.GetFullPath(source), destination);
                if (move) lease.DeleteVerifiedOriginals();
            }
        }
        public void Mount(string drive)
        {
            if (drive == null || drive.Length != 3 || drive[1] != ':' || drive[2] != '\\' || drive[0] < 'D' || drive[0] > 'Z')
                throw new IOException("Выберите свободную букву диска D–Z.");
            if (Directory.Exists(drive)) throw new IOException("Буква диска уже занята.");
            Call("mount", drive); MountPoint = drive;
        }
        public void Dispose()
        {
            if(Interlocked.Exchange(ref disposed,1)!=0) return;
            var p = Interlocked.Exchange(ref process,null);
            if (p != null) {
                try { p.StandardInput.Close(); if (!p.WaitForExit(1500)) p.Kill(); } catch { try { p.Kill(); } catch { } }
                p.Dispose();
            }
            foreach (var handle in runtimeLocks) handle.Dispose(); runtimeLocks.Clear();
            if(runtimeDirectories!=null) runtimeDirectories.Dispose();
            MountPoint = null;
        }
        // Cancellation must not wait for a large transfer on the UI thread.
        public void Cancel() { var p = process; if (p != null) try { p.Kill(); } catch { } }
    }

    internal static class SafePaths
    {
        public static bool IsWithin(string child, string parent) {
            var a = Path.GetFullPath(child).TrimEnd('\\'); var b = Path.GetFullPath(parent).TrimEnd('\\');
            return a.Equals(b, StringComparison.OrdinalIgnoreCase) || a.StartsWith(b + "\\", StringComparison.OrdinalIgnoreCase);
        }
        public static string Child(string root, string relative) {
            string result = Path.GetFullPath(Path.Combine(root, relative.Replace('/', '\\')));
            if (!IsWithin(result, root) || result.Equals(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase)) throw new IOException("Недопустимый путь.");
            return result;
        }
        public static void NoReparseParents(string path) {
            string current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current)) {
                if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Ссылки и точки перенаправления в пути не поддерживаются: " + current);
                current = Path.GetDirectoryName(current);
            }
        }
    }

    // Open originals with DELETE permission but without sharing write/delete access.
    // They stay unchanged until encrypted data has been read back and verified.
    // Delete uses these same handles, preventing a path substitution race.
    internal sealed class SourceLease : IDisposable
    {
        readonly List<SafeFileHandle> files = new List<SafeFileHandle>();
        readonly List<string> directories = new List<string>();
        readonly List<SafeFileHandle> directoryLocks = new List<SafeFileHandle>();
        [StructLayout(LayoutKind.Sequential)] struct HandleInfo {
            public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
                Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out HandleInfo info);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, ref int info, uint size);
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct StreamData { public long Size; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=296)] public string Name; }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr FindFirstStreamW(string path,int info,out StreamData data,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool FindNextStreamW(IntPtr handle,out StreamData data);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr handle);
        static void RejectNamedStreams(string path) {
            StreamData stream; IntPtr h=FindFirstStreamW(path,0,out stream,0);
            if(h==new IntPtr(-1)) {
                int error=Marshal.GetLastWin32Error();
                if(error==38 || error==1 || error==87) return;
                throw new IOException("Не удалось проверить дополнительные потоки файла: "+path);
            }
            try { do { if(stream.Name!="::$DATA") throw new IOException("У файла есть дополнительные потоки NTFS. Такой файл нельзя перенести без потери данных: "+path); } while(FindNextStreamW(h,out stream)); }
            finally { FindClose(h); }
        }
        public static SourceLease Acquire(string source, bool move) {
            var result = new SourceLease();
            try {
                source=Path.GetFullPath(source); SafePaths.NoReparseParents(source);
                // Hold each ancestor before descending. A parent junction or rename must
                // not redirect the helper between verification and reading the source.
                var parents=new Stack<string>();
                for(string p=Path.GetDirectoryName(source);!string.IsNullOrEmpty(p);p=Path.GetDirectoryName(p)) parents.Push(p);
                while(parents.Count>0) {
                    string p=parents.Pop();
                    var h=CreateFile(p,0x80u,1,IntPtr.Zero,3,0x02200000u,IntPtr.Zero);
                    HandleInfo info;
                    if(h.IsInvalid || !GetFileInformationByHandle(h,out info) || (info.Attributes & 0x400u)!=0) { h.Dispose(); throw new IOException("Исходный путь занят или содержит ссылку: "+p); }
                    result.directoryLocks.Add(h);
                }
                result.Visit(source, move); return result;
            }
            catch { result.Dispose(); throw; }
        }
        internal static SourceLease HoldDirectories(string directory) {
            var result=new SourceLease();
            try {
                var parents=new Stack<string>();
                for(string p=Path.GetFullPath(directory);!string.IsNullOrEmpty(p);p=Path.GetDirectoryName(p)) parents.Push(p);
                while(parents.Count>0) {
                    string p=parents.Pop(); var h=CreateFile(p,0x80u,1,IntPtr.Zero,3,0x02200000u,IntPtr.Zero);
                    HandleInfo info;
                    if(h.IsInvalid || !GetFileInformationByHandle(h,out info) || (info.Attributes & 0x400u)!=0 || (info.Attributes & 0x10u)==0) {
                        h.Dispose(); throw new IOException("Папка обновлений занята или содержит ссылку: "+p);
                    }
                    result.directoryLocks.Add(h);
                }
                return result;
            } catch { result.Dispose(); throw; }
        }
        void Visit(string path, bool move) {
            if(files.Count+directories.Count>=10000) throw new IOException("За один раз можно добавить до 10 000 файлов и папок.");
            var attrs = File.GetAttributes(path);
            if ((attrs & FileAttributes.ReparsePoint) != 0) throw new IOException("Ссылки в исходной папке не поддерживаются.");
            bool directory = (attrs & FileAttributes.Directory) != 0;
            var handle = CreateFile(path, directory ? 0x80u : 0x80000000u | (move ? 0x10000u : 0u), 1, IntPtr.Zero, 3, directory ? 0x02200000u : 0x00200000u, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new IOException("Файл занят или недоступен: " + path); }
            HandleInfo info;
            if(!GetFileInformationByHandle(handle,out info) || (info.Attributes & 0x400u)!=0 || ((info.Attributes & 0x10u)!=0)!=directory) {
                handle.Dispose(); throw new IOException("Исходный путь изменился или содержит ссылку: "+path);
            }
            try { RejectNamedStreams(path); } catch { handle.Dispose(); throw; }
            if (!directory) { files.Add(handle); return; }
            directoryLocks.Add(handle); directories.Add(path);
            foreach (string child in Directory.GetFileSystemEntries(path)) Visit(child, move);
        }
        public void DeleteVerifiedOriginals() {
            foreach (var file in files) {
                int disposition = 1;
                if (!SetFileInformationByHandle(file, 4, ref disposition, 4)) throw new IOException("Зашифрованная копия проверена, но часть исходников не удалось удалить.");
                file.Dispose();
            }
            foreach (var handle in directoryLocks) handle.Dispose(); directoryLocks.Clear();
            foreach (string dir in directories.OrderByDescending(x => x.Length)) {
                try { Directory.Delete(dir, false); }
                catch { throw new IOException("Файлы перенесены. Исходная папка сохранена: она занята или в ней появились новые файлы."); }
            }
        }
        public void Dispose() { foreach (var f in files) f.Dispose(); foreach (var d in directoryLocks) d.Dispose(); }
    }
}

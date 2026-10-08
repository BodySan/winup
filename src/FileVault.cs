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
        SourceLease vaultDirectories;
        public string Folder { get; private set; }
        public string MountPoint { get; private set; }
        public bool Open { get { var p=process; try { return p != null && !p.HasExited; } catch { return false; } } }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateDirectoryW(string path, IntPtr security);

        public FileVaultClient(string folder, string password, bool create, CancellationToken cancellation = default(CancellationToken))
        {
            Folder = Path.GetFullPath(folder);
            SafePaths.NoReparseParents(Folder);
            try
            {
                // Keep the selected path stable while the helper opens/creates the vault.
                // A junction or renamed ancestor must not redirect it elsewhere.
                vaultDirectories = SourceLease.HoldDirectories(create ? Path.GetDirectoryName(Folder) : Folder);
                string root = ExtractRuntime(runtimeLocks,out runtimeDirectories);
                cancellation.ThrowIfCancellationRequested();
                if (create) {
                    // Win32 creation fails if ANY object already occupies this name.
                    // Hold and validate the newly created root before passing secrets
                    // to the helper, eliminating its mkdir-to-first-write gap.
                    if (!CreateDirectoryW(Folder, IntPtr.Zero)) throw new IOException("Не удалось создать новую папку хранилища. Выберите свободное имя и доступную папку.");
                    var createdDirectories = SourceLease.HoldDirectories(Folder);
                    vaultDirectories.Dispose(); vaultDirectories = createdDirectories;
                }
                var info = new ProcessStartInfo(Path.Combine(root, "WinUpFiles.exe")) {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
                    WorkingDirectory = root };
                process = Process.Start(info);
                process.ErrorDataReceived += delegate { }; // never persist paths or secrets from diagnostics
                process.BeginErrorReadLine();
                using (cancellation.Register(Cancel)) Call(create ? "create" : "open", Folder, password, vaultDirectories.GuardName);
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
                    if (!hashes.ContainsKey(relative) && !directories.IsGuardFile(path)) throw new IOException("В папке файлового модуля обнаружен посторонний файл.");
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
                SourceLease exportDirectories = null;
                string exportStage = null;
                bool receivedResult = false;
                bool commandSent = false;
                try
                {
                    if (command == "export") {
                        if (fields.Length != 2) throw new IOException("Недопустимая команда экспорта.");
                        string destination = Path.GetFullPath(fields[1]);
                        SafePaths.NoReparseParents(destination);
                        if (SafePaths.IsWithin(destination, Folder) ||
                            MountPoint != null && SafePaths.IsWithin(destination, MountPoint))
                            throw new IOException("Выберите папку за пределами зашифрованного хранилища и его диска.");
                        exportDirectories = SourceLease.HoldDirectories(Path.GetDirectoryName(destination));
                        exportStage = Path.Combine(Path.GetDirectoryName(destination), ".winup-export-" + Guid.NewGuid().ToString("N"));
                        fields = new[] { fields[0], destination, exportStage };
                    }
                    foreach (string field in fields)
                    {
                        byte[] bytes = Encoding.UTF8.GetBytes(field ?? "");
                        try { encoded.Add(Convert.ToBase64String(bytes)); }
                        finally { Array.Clear(bytes,0,bytes.Length); }
                    }
                    line = command + "\t" + string.Join("\t", encoded);
                    if (line.Length > 8 * 1024 * 1024) throw new IOException("Слишком большой список файлов для одной операции.");
                    commandSent = true;
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
                    if (result == null || !result.ContainsKey("ok") || !(result["ok"] is bool)) throw new IOException("Файловый модуль нарушил протокол.");
                    receivedResult = true;
                    if (!(bool)result["ok"])
                        throw new IOException("Операция не выполнена: " + (result != null && result.ContainsKey("error") ? result["error"] : "сбой модуля") +
                            (result != null && result.ContainsKey("detail") ? " — " + result["detail"] : ""));
                    return result;
                }
                catch {
                    // A broken reply cannot leave a writer alive with an unknown state.
                    if (commandSent && !receivedResult) { Cancel(); var failed = process; if (failed != null) try { failed.WaitForExit(3000); } catch { } }
                    throw;
                }
                finally {
                    try {
                        // Process termination skips Java's finally blocks. The parent
                        // owns this exact staging name and removes partial plaintext.
                        if (exportStage != null) File.Delete(exportStage);
                    } catch (Exception cleanup) { throw new IOException("Не удалось удалить незавершённую расшифрованную копию: " + exportStage, cleanup); }
                    finally { if (exportDirectories != null) exportDirectories.Dispose(); Secure.Wipe(line); foreach (string field in encoded) Secure.Wipe(field); }
                }
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
                // Import exactly the locked snapshot. Files created after acquisition
                // are never read by an unprotected second directory traversal.
                string manifest = new JavaScriptSerializer { MaxJsonLength = 6 * 1024 * 1024 }.Serialize(lease.Snapshot);
                try { Call("import", Path.GetFullPath(source), destination, manifest); }
                finally { Secure.Wipe(manifest); }
                if (move) lease.DeleteVerifiedOriginals();
            }
        }
        public void Mount(string drive)
        {
            if (drive == null || drive.Length != 3 || drive[1] != ':' || drive[2] != '\\' || drive[0] < 'D' || drive[0] > 'Z')
                throw new IOException("Выберите свободную букву диска D–Z.");
            if (Directory.Exists(drive)) throw new IOException("Буква диска уже занята.");
            WinFspDriver.EnsureRunning();
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
            if(vaultDirectories!=null) vaultDirectories.Dispose();
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
        readonly List<string> filePaths = new List<string>();
        readonly List<string> directories = new List<string>();
        readonly List<SafeFileHandle> directoryLocks = new List<SafeFileHandle>();
        readonly List<SafeFileHandle> directoryGuards = new List<SafeFileHandle>();
        string guardPath;
        internal string GuardName { get { return guardPath == null ? "" : Path.GetFileName(guardPath); } }
        internal bool IsGuardFile(string path) { return guardPath != null && guardPath.Equals(Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase); }
        readonly Dictionary<string, SafeFileHandle> originalDirectories = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> snapshot = new List<string>();
        string sourceRoot;
        internal string[] Snapshot { get { return snapshot.ToArray(); } }
        [StructLayout(LayoutKind.Sequential)] struct HandleInfo {
            public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
                Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out HandleInfo info);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int kind,IntPtr information,uint size);
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
            try {
                do { if(stream.Name!="::$DATA") throw new IOException("У файла есть дополнительные потоки NTFS. Такой файл нельзя перенести без потери данных: "+path); } while(FindNextStreamW(h,out stream));
                if (Marshal.GetLastWin32Error() != 38) throw new IOException("Не удалось полностью проверить дополнительные потоки файла: " + path);
            }
            finally { FindClose(h); }
        }
        static void RejectNamedStreams(SafeFileHandle handle) {
            // Query the already-held object. Delete-pending paths intentionally
            // cannot be reopened, including newly created alternate streams.
            const int capacity = 65536;
            IntPtr buffer = Marshal.AllocHGlobal(capacity);
            try {
                Marshal.WriteInt32(buffer, 0, 0); Marshal.WriteInt32(buffer, 4, 0);
                if (!GetFileInformationByHandleEx(handle, 7, buffer, capacity)) {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 38 || error == 1 || error == 50 || error == 87) return;
                    throw new IOException("Не удалось проверить потоки исходника перед удалением.");
                }
                int offset = 0;
                while (true) {
                    if (offset < 0 || offset > capacity - 24) throw new IOException("Повреждён список потоков исходника.");
                    int next = Marshal.ReadInt32(buffer, offset), length = Marshal.ReadInt32(buffer, offset + 4);
                    if (length <= 0 || (length & 1) != 0 || length > capacity - offset - 24) throw new IOException("Повреждён список потоков исходника.");
                    string name = Marshal.PtrToStringUni(new IntPtr(buffer.ToInt64() + offset + 24), length / 2);
                    if (name != "::$DATA") throw new IOException("У исходника появился дополнительный поток NTFS. Исходники сохранены.");
                    if (next == 0) break;
                    if (next < 24 + length || (next & 7) != 0 || next > capacity - offset) throw new IOException("Повреждён список потоков исходника.");
                    offset += next;
                }
            } finally { Marshal.FreeHGlobal(buffer); }
        }
        public static SourceLease Acquire(string source, bool move) {
            var result = new SourceLease();
            try {
                source=Path.GetFullPath(source); SafePaths.NoReparseParents(source);
                result.sourceRoot = source;
                var parents=new Stack<string>();
                for(string p=Path.GetDirectoryName(source);!string.IsNullOrEmpty(p);p=Path.GetDirectoryName(p)) parents.Push(p);
                var paths=new List<string>();
                while(parents.Count>0) {
                    string p=parents.Pop();var h=CreateFile(p,0x80000000u,1,IntPtr.Zero,3,0x02200000u,IntPtr.Zero);
                    HandleInfo info;
                    if(h.IsInvalid || !GetFileInformationByHandle(h,out info) || (info.Attributes & 0x410u)!=0x10u) {h.Dispose();throw new IOException("Исходный путь занят или содержит ссылку: "+p);}
                    result.directoryLocks.Add(h);paths.Add(p);
                }
                // The held source itself anchors its parent. Reading/copying a
                // source never needs permission to create a guard beside it.
                result.Visit(source, move); result.AllowChildWrites(paths); return result;
            }
            catch { result.Dispose(); throw; }
        }
        internal static SourceLease HoldDirectories(string directory) {
            var result=new SourceLease();
            try {
                // Attribute-only access ignores sharing restrictions. Read access
                // denies directory deletion, but denying directory writes also
                // blocks normal child-file renames. Bootstrap without write
                // sharing, create an undeletable child, then allow child writes.
                // The held child prevents converting an empty directory to a
                // junction; every ancestor has its held descendant as an anchor.
                var parents=new Stack<string>();
                for(string p=Path.GetFullPath(directory);!string.IsNullOrEmpty(p);p=Path.GetDirectoryName(p)) parents.Push(p);
                var paths=new List<string>();
                while(parents.Count>0) {
                    string p=parents.Pop(); var h=CreateFile(p,0x80000000u,1,IntPtr.Zero,3,0x02200000u,IntPtr.Zero);
                    HandleInfo info;
                    if(h.IsInvalid || !GetFileInformationByHandle(h,out info) || (info.Attributes & 0x400u)!=0 || (info.Attributes & 0x10u)==0) {
                        h.Dispose(); throw new IOException("Папка обновлений занята или содержит ссылку: "+p);
                    }
                    result.directoryLocks.Add(h); paths.Add(p);
                }
                result.guardPath=Path.Combine(Path.GetFullPath(directory),".winup-path-lease-"+Guid.NewGuid().ToString("N"));
                var guard=CreateFile(result.guardPath,0x80010000u,3,IntPtr.Zero,1,0x04200102u,IntPtr.Zero);
                if(guard.IsInvalid) { guard.Dispose(); throw new IOException("Не удалось удержать папку для безопасной записи: "+directory); }
                result.directoryGuards.Add(guard);
                result.AllowChildWrites(paths);
                return result;
            } catch { result.Dispose(); throw; }
        }
        void AllowChildWrites(List<string> paths) {
                for(int i=0;i<paths.Count;i++) {
                    var h=CreateFile(paths[i],0x80000000u,3,IntPtr.Zero,3,0x02200000u,IntPtr.Zero);
                    HandleInfo info;
                    if(h.IsInvalid || !GetFileInformationByHandle(h,out info) || (info.Attributes & 0x400u)!=0 || (info.Attributes & 0x10u)==0) {
                        h.Dispose(); throw new IOException("Папка изменилась при удержании: "+paths[i]);
                    }
                    directoryLocks[i].Dispose(); directoryLocks[i]=h;
                }
        }
        void Visit(string path, bool move) {
            if(files.Count+directories.Count>=10000) throw new IOException("За один раз можно добавить до 10 000 файлов и папок.");
            var attrs = File.GetAttributes(path);
            if ((attrs & FileAttributes.ReparsePoint) != 0) throw new IOException("Ссылки в исходной папке не поддерживаются.");
            bool directory = (attrs & FileAttributes.Directory) != 0;
            var handle = CreateFile(path, 0x80000000u | (move ? 0x10000u : 0u), 1, IntPtr.Zero, 3, directory ? 0x02200000u : 0x00200000u, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new IOException("Файл занят или недоступен: " + path); }
            HandleInfo info;
            if(!GetFileInformationByHandle(handle,out info) || (info.Attributes & 0x400u)!=0 || ((info.Attributes & 0x10u)!=0)!=directory) {
                handle.Dispose(); throw new IOException("Исходный путь изменился или содержит ссылку: "+path);
            }
            try { RejectNamedStreams(path); } catch { handle.Dispose(); throw; }
            snapshot.Add(path.Equals(sourceRoot, StringComparison.OrdinalIgnoreCase) ? "" : path.Substring(sourceRoot.Length + 1));
            if (!directory) { files.Add(handle); filePaths.Add(path); return; }
            directoryLocks.Add(handle); directories.Add(path);
            originalDirectories.Add(path, handle);
            foreach (string child in Directory.GetFileSystemEntries(path)) Visit(child, move);
        }
        public void DeleteVerifiedOriginals() {
            // NTFS share modes apply per stream. A newly added named stream can
            // appear after the initial snapshot without changing default data.
            // Validate the complete set before deleting even the first original.
            foreach (string path in filePaths.Concat(directories)) RejectNamedStreams(path);
            var marked = new List<SafeFileHandle>();
            try {
                // Do not close the first file until every original has passed the
                // final stream check under delete-pending. New stream opens fail.
                foreach (var file in files) {
                    int disposition = 1;
                    if (!SetFileInformationByHandle(file, 4, ref disposition, 4)) throw new IOException("Зашифрованная копия проверена, но исходники не удалось удалить.");
                    marked.Add(file);
                }
                foreach (var file in marked) RejectNamedStreams(file);
            } catch {
                bool restored = true;
                foreach (var file in marked) { int disposition = 0; if (!SetFileInformationByHandle(file, 4, ref disposition, 4)) restored = false; }
                if (!restored) throw new IOException("Не удалось отменить удаление части исходников. Их зашифрованная копия уже проверена.");
                throw;
            }
            foreach (var file in files) file.Dispose();
            foreach (string dir in directories.OrderByDescending(x => x.Length)) {
                var handle = originalDirectories[dir]; int disposition = 1;
                if (!SetFileInformationByHandle(handle, 4, ref disposition, 4))
                    throw new IOException("Файлы перенесены. Исходная папка сохранена: она занята или в ней появились новые файлы.");
                try { RejectNamedStreams(handle); }
                catch { disposition = 0; if (!SetFileInformationByHandle(handle, 4, ref disposition, 4)) throw new IOException("Не удалось отменить удаление исходной папки. Зашифрованная копия уже проверена."); throw; }
                handle.Dispose();
            }
            foreach (var handle in directoryLocks) handle.Dispose(); directoryLocks.Clear();
        }
        public void Dispose() { foreach (var f in files) f.Dispose(); foreach (var g in directoryGuards) g.Dispose(); foreach (var d in directoryLocks) d.Dispose(); }
    }
}

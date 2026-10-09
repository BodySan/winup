using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace WinUp
{
    // Все пути — относительно папки, где лежит WinUp.exe: папку можно переносить целиком.
    static class Paths
    {
        static Paths()
        {
            AppContext.SetSwitch("Switch.System.IO.UseLegacyPathHandling", false);
            AppContext.SetSwitch("Switch.System.IO.BlockLongPaths", false);
        }
        // WinUp.exe в корне диска (например, флешка E:\): после TrimEnd остаётся "E:", и тогда
        // Path.Combine("E:", "data") = "E:data" — drive-relative путь, который резолвится от текущего
        // каталога диска и «плывёт» после файловых диалогов. Корню диска возвращаем слэш.
        // Data и остальные пути — свойства, вычисляются при обращении, т.е. уже от исправленного Root.
        public static readonly string Root = FixRoot(AppDomain.CurrentDomain.BaseDirectory);

        static string FixRoot(string dir)
        {
            var r = dir.TrimEnd('\\');
            if (r.Length == 2 && r[1] == ':') r += "\\";
            return r;
        }

        // Корень с хвостовым слэшем — общий префикс для сравнений (без удвоения, когда корень — "E:\").
        internal static string RootPrefix { get { return Root.EndsWith("\\") ? Root : Root + "\\"; } }

        public static string Data { get { return Path.Combine(Root, "data"); } }
        public static string Apps { get { return Path.Combine(Root, "apps"); } }
        public static string AppsFile { get { return Path.Combine(Data, "apps.json"); } }
        public static string VaultFile { get { return Path.Combine(Data, "vault.dat"); } }
        // Путь базы kdbx без обращения к KdbxStore: тот тянет KeePassLib, а списку программ ядро не нужно.
        public static string KdbxFile { get { return Path.Combine(Data, "vault.kdbx"); } }

        // Файлы, вшитые в exe (WinUp можно передать одним файлом): Инструкция.html и лицензия ядра THIRD-PARTY.md.
        // Файл рядом с exe главнее — его могли обновить отдельно.
        public static readonly string[] Bundled = { "Инструкция.html", "THIRD-PARTY.md" };
        static string ResourceOf(string file) { return file == "Инструкция.html" ? "help.html" : file; }

        public static Stream OpenBundled(string file)
        {
            var p = Path.Combine(Root, file);
            if (System.IO.File.Exists(p)) return System.IO.File.OpenRead(p);
            return typeof(Paths).Assembly.GetManifestResourceStream(ResourceOf(file));
        }

        public static bool CopyBundled(string file, string dst)
        {
            using (var s = OpenBundled(file))
            {
                if (s == null) return false;
                using (var f = new FileStream(dst, FileMode.Create, FileAccess.Write)) s.CopyTo(f);
                return true;
            }
        }

        // Относительный путь — от папки WinUp; допускаются переменные вида %ProgramFiles%.
        public static string Full(string p)
        {
            if (string.IsNullOrEmpty(p)) return p;
            p = Environment.ExpandEnvironmentVariables(p);
            return Path.IsPathRooted(p) ? p : Path.Combine(Root, p);
        }

        public static string Rel(string full)
        {
            var r = RootPrefix;
            return full.StartsWith(r, StringComparison.OrdinalIgnoreCase) ? full.Substring(r.Length) : full;
        }

        public static bool IsUnderRoot(string full)
        {
            return full.StartsWith(RootPrefix, StringComparison.OrdinalIgnoreCase);
        }

        // Запись через временный файл: при сбое посередине старый файл остаётся целым,
        // предыдущая версия сохраняется как .bak.
        static readonly object writeSync = new object();

        // Keep every existing directory stable while creating children. Checking a
        // path and then opening it is insufficient when another process can rename it.
        internal static IDisposable HoldWriteDirectory(string directory)
        {
            var held = new WriteDirectoryLease();
            try
            {
                var missing = new Stack<string>();
                var current = Path.GetFullPath(directory);
                while (!Directory.Exists(current))
                {
                    missing.Push(current);
                    current = Path.GetDirectoryName(current);
                    if (string.IsNullOrEmpty(current)) throw new IOException("Не найден корень папки для записи.");
                }
                held.Items.Add(SourceLease.HoldDirectories(current));
                while (missing.Count != 0)
                {
                    var child = missing.Pop();
                    Directory.CreateDirectory(child);
                    held.Items.Add(SourceLease.HoldDirectories(child));
                }
                return held;
            }
            catch { held.Dispose(); throw; }
        }

        sealed class WriteDirectoryLease : IDisposable
        {
            internal readonly List<SourceLease> Items = new List<SourceLease>();
            public void Dispose() { for (int i = Items.Count - 1; i >= 0; --i) Items[i].Dispose(); Items.Clear(); }
        }

        public static void AtomicWrite(string path, byte[] data)
        {
            if (data == null) throw new ArgumentNullException("data");
            AtomicWriteStream(path, stream => stream.Write(data, 0, data.Length));
        }

        internal static void AtomicWriteStream(string path, Action<Stream> write)
        {
            if (write == null) throw new ArgumentNullException("write");
            path = Path.GetFullPath(path);
            var name = Path.GetFileName(path);
            if (string.IsNullOrEmpty(name) || name.IndexOf(':') >= 0 || name.EndsWith(".") || name.EndsWith(" "))
                throw new IOException("Недопустимое имя файла для записи.");
            lock (writeSync)
            using (HoldWriteDirectory(Path.GetDirectoryName(path)))
                AtomicWriteHeld(path, write);
        }

        internal sealed class LeaveOpenStream : Stream
        {
            readonly Stream inner;
            internal LeaveOpenStream(Stream stream) { inner = stream; }
            public override bool CanRead { get { return inner.CanRead; } }
            public override bool CanSeek { get { return inner.CanSeek; } }
            public override bool CanWrite { get { return inner.CanWrite; } }
            public override long Length { get { return inner.Length; } }
            public override long Position { get { return inner.Position; } set { inner.Position = value; } }
            public override void Flush() { inner.Flush(); }
            public override int Read(byte[] buffer, int offset, int count) { return inner.Read(buffer, offset, count); }
            public override long Seek(long offset, SeekOrigin origin) { return inner.Seek(offset, origin); }
            public override void SetLength(long value) { inner.SetLength(value); }
            public override void Write(byte[] buffer, int offset, int count) { inner.Write(buffer, offset, count); }
            protected override void Dispose(bool disposing) { if (disposing) inner.Flush(); }
        }

        static void AtomicWriteHeld(string path, Action<Stream> write)
        {
            SafePaths.NoReparseParents(path);
            SafePaths.NoReparseParents(path + ".bak");
            var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    write(fs);
                    fs.Flush(true);
                }
                if (File.Exists(path))
                {
                    try { File.Replace(tmp, path, path + ".bak"); }
                    catch (IOException)
                    {
                        // Антивирус или залоченный .bak могут на миг держать файл — один ретрай после паузы.
                        System.Threading.Thread.Sleep(150);
                        File.Replace(tmp, path, path + ".bak");
                    }
                }
                else File.Move(tmp, path);
            }
            finally
            {
                // При любом сбое старый файл остаётся цел; неперенесённый tmp подчищаем, чтобы не копился мусор.
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
        }
        internal static string[] AtomicRemnants(string path)
        {
            var directory = Path.GetDirectoryName(path);
            if (!Directory.Exists(directory)) return new string[0];
            string name = Path.GetFileName(path);
            return Directory.GetFiles(directory, name + "*.tmp").Where(file =>
                string.Equals(Path.GetFileName(file), name + ".tmp", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(Path.GetFileName(file), "^" + Regex.Escape(name) + @"\.[0-9a-fA-F]{32}\.tmp$")).ToArray();
        }

        sealed class AtomicBatchFile
        {
            internal string Path, Temporary, OldBackup;
            internal Action<Stream> Write;
            internal bool Existed, HadBackup, Committed, KeepOldBackup;
        }

        // All serializers finish before any target changes. A running-process
        // failure restores both the previous targets and their existing backups.
        internal static void AtomicWriteBatch(List<KeyValuePair<string, Action<Stream>>> writes)
        {
            if (writes == null || writes.Count == 0) throw new ArgumentException("Пустой набор файлов.");
            lock (writeSync)
            {
                var files = new List<AtomicBatchFile>();
                string directory = null;
                foreach (var write in writes)
                {
                    if (write.Value == null) throw new ArgumentNullException("write");
                    string path = Path.GetFullPath(write.Key), name = Path.GetFileName(path);
                    if (string.IsNullOrEmpty(name) || name.IndexOf(':') >= 0 || name.EndsWith(".") || name.EndsWith(" "))
                        throw new IOException("Недопустимое имя файла для записи.");
                    string parent = Path.GetDirectoryName(path);
                    if (directory == null) directory = parent;
                    if (!string.Equals(parent, directory, StringComparison.OrdinalIgnoreCase) || files.Any(x =>
                        string.Equals(x.Path, path, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(x.Path + ".bak", path, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(x.Path, path + ".bak", StringComparison.OrdinalIgnoreCase)))
                        throw new IOException("Неверный набор файлов сохранения.");
                    files.Add(new AtomicBatchFile { Path = path, Write = write.Value });
                }
                using (HoldWriteDirectory(directory))
                try
                {
                    foreach (var file in files)
                    {
                        SafePaths.NoReparseParents(file.Path); SafePaths.NoReparseParents(file.Path + ".bak");
                        file.Existed = File.Exists(file.Path);
                        file.HadBackup = file.Existed && File.Exists(file.Path + ".bak");
                        file.Temporary = file.Path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                        using (var stream = new FileStream(file.Temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        { file.Write(stream); stream.Flush(true); }
                        if (file.HadBackup)
                        {
                            // Use the same remnant pattern as serializer staging so
                            // password rotation and destruction can also remove it.
                            file.OldBackup = file.Path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                            using (var source = new FileStream(file.Path + ".bak", FileMode.Open, FileAccess.Read, FileShare.Read))
                            using (var destination = new FileStream(file.OldBackup, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                            { source.CopyTo(destination); destination.Flush(true); }
                        }
                    }
                    foreach (var file in files)
                    {
                        if (file.Existed) File.Replace(file.Temporary, file.Path, file.Path + ".bak");
                        else File.Move(file.Temporary, file.Path);
                        file.Committed = true;
                    }
                }
                catch (Exception original)
                {
                    var rollbackErrors = new List<string>();
                    for (int i = files.Count - 1; i >= 0; --i)
                    {
                        var file = files[i];
                        if (!file.Committed) continue;
                        try
                        {
                            if (file.Existed) File.Replace(file.Path + ".bak", file.Path, null);
                            else File.Delete(file.Path);
                        }
                        catch (Exception failure)
                        {
                            // The current .bak still holds the original target.
                            // Keep its older backup as well if restoration failed.
                            file.KeepOldBackup = true;
                            rollbackErrors.Add(Path.GetFileName(file.Path) + ": " + failure.Message);
                            continue;
                        }
                        if (file.HadBackup)
                        {
                            try { File.Move(file.OldBackup, file.Path + ".bak"); }
                            catch (Exception failure)
                            {
                                file.KeepOldBackup = true;
                                rollbackErrors.Add(Path.GetFileName(file.Path + ".bak") + ": " + failure.Message +
                                    "; прежняя копия: " + Path.GetFileName(file.OldBackup));
                            }
                        }
                    }
                    if (rollbackErrors.Count != 0) throw new IOException("Сохранение прервано; восстановление прежнего состояния не завершено: " + string.Join("; ", rollbackErrors) + ". Откройте базу заново или восстановите резерв.", original);
                    throw new IOException("Сохранение отменено. Прежние файлы сохранены или восстановлены.", original);
                }
                finally
                {
                    foreach (var file in files)
                    {
                        try { if (file.Temporary != null) File.Delete(file.Temporary); } catch { }
                        try { if (!file.KeepOldBackup && file.OldBackup != null) File.Delete(file.OldBackup); } catch { }
                    }
                }
            }
        }
    }

    public class AppItem
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string File { get; set; }
        public string Kind { get; set; }   // "install" | "portable"
        public string Args { get; set; }
        public string Note { get; set; }
        public string Description { get; set; }
        public bool Admin { get; set; }      // запускать от администратора

        public bool Exists
        {
            get
            {
                try { var p = Paths.Full(File); return System.IO.File.Exists(p) || Directory.Exists(p); }
                catch (ArgumentException) { return false; } // недопустимые символы в пути
            }
        }
    }

    // Ссылка на официальную страницу загрузки.
    public class LinkItem
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Url { get; set; }
        public string Description { get; set; }
    }

    // Шаблон записи для входа: всё, кроме логина и пароля.
    public class LoginTemplate
    {
        public string Name { get; set; }
        public string Group { get; set; }
        public string Category { get; set; }
        public string Kind { get; set; }      // "site" | "app"
        public string Target { get; set; }
        public string AppTarget { get; set; }
        public string LoginUrl { get; set; }
        public string LoginProfile { get; set; }
        public string Args { get; set; }
        public string Window { get; set; }
        public bool AutoEnter { get; set; }
        public string TwoFa { get; set; }     // "none" | "ask" | "totp"
        public string Note { get; set; }
    }

    public class Settings
    {
        public int AutoLockMinutes { get; set; }
        public string BackupDir { get; set; }
        public int BackupKeep { get; set; }
        public string Browser { get; set; }            // "" — браузер по умолчанию
        public List<string> IgnoredFiles { get; set; } // файлы в apps\, которые не предлагать
        public int DefaultsVersion { get; set; }       // какая версия встроенных шаблонов и ссылок уже добавлена
        public bool WizardDone { get; set; }           // мастер первого запуска пройден или пропущен
        public bool HideFromCapture { get; set; }      // окна WinUp не видны записи экрана и удалённому доступу
        public string LastKeyFile { get; set; }        // путь последнего ключ-файла (подстановка при входе)
        public bool FillNotify { get; set; }           // уведомление о каждой вставке пароля расширением браузера
        public bool MinimizeToTray { get; set; }       // галочка меняет поведение кнопки сворачивания
        // Папка резерва по умолчанию — в «Документах» того, кто запустил WinUp (вне папки программы).
        public static string DefaultBackupDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WinUp резерв"); }
        }

        public Settings()
        {
            AutoLockMinutes = 10; BackupDir = DefaultBackupDir; BackupKeep = 20; HideFromCapture = true; FillNotify = true;
            Browser = ""; IgnoredFiles = new List<string>(); LastKeyFile = "";
        }
    }

    public class AppStore
    {
        public List<AppItem> Apps { get; set; }
        public List<LinkItem> Links { get; set; }
        public List<LoginTemplate> Templates { get; set; }
        public List<WingetPackage> Winget { get; set; }   // «Мой набор» из каталога winget
        public Settings Settings { get; set; }
        public AppStore() { Apps = new List<AppItem>(); Links = new List<LinkItem>(); Templates = new List<LoginTemplate>(); Winget = new List<WingetPackage>(); Settings = new Settings(); }

        // Первый запуск — список создаётся из встроенных шаблонов и ссылок. Если встроенный набор новее
        // сохранённого — недостающие шаблоны и ссылки добавляются, правки пользователя не трогаются.
        // readOnly — дочерний процесс --install: список читается, но не записывается (основной работает).
        public static AppStore Load(bool readOnly = false)
        {
            var d = Defaults.Load();
            if (!System.IO.File.Exists(Paths.AppsFile))
            {
                var fresh = new AppStore { Links = d.Links, Templates = d.Templates };
                fresh.Settings.DefaultsVersion = d.Version;
                if (!readOnly) fresh.Save();
                return fresh;
            }
            // Сверка с отпечатком — до любой записи: иначе пополнение встроенного набора ниже
            // сохранило бы подменённый файл как «свой» и спрятало подмену.
            try
            {
                var pinned = Integrity.GetApps();
                var cur = Integrity.AppsHash();
                if (!string.IsNullOrEmpty(pinned) && cur != null && pinned != cur) ChangedOutside = cur;
            }
            catch { }
            var s = Json.Read<AppStore>(SafeStorage.ReadTextBounded(Paths.AppsFile, 16 * 1024 * 1024));
            if (s == null) throw new InvalidDataException("Список WinUp повреждён: вместо объекта записан null. Восстановите apps.json из резерва.");
            if (s.Apps == null) s.Apps = new List<AppItem>();
            if (s.Links == null) s.Links = new List<LinkItem>();
            if (s.Templates == null) s.Templates = new List<LoginTemplate>();
            if (s.Settings == null) s.Settings = new Settings();
            s.Apps.RemoveAll(x => x == null);
            s.Links.RemoveAll(x => x == null);
            s.Templates.RemoveAll(x => x == null);
            s.Settings.AutoLockMinutes = Math.Max(1, Math.Min(1440, s.Settings.AutoLockMinutes));
            s.Settings.BackupKeep = Math.Max(1, Math.Min(1000, s.Settings.BackupKeep));
            if (s.Settings.IgnoredFiles == null) s.Settings.IgnoredFiles = new List<string>();
            if (s.Settings.Browser == null) s.Settings.Browser = "";
            // Пусто — копия для передачи (путь отправителя ей не нужен): резерв в «Документах» этого пользователя.
            if (string.IsNullOrWhiteSpace(s.Settings.BackupDir)) s.Settings.BackupDir = Settings.DefaultBackupDir;
            if (s.Winget == null) s.Winget = new List<WingetPackage>();
            s.Winget.RemoveAll(x => x == null);
            if (s.Settings.DefaultsVersion < d.Version)
            {
                var had = s.Links.ToList(); // сравниваем только с тем, что было у пользователя
                foreach (var l in d.Links)
                    if (!had.Any(x => string.Equals(x.Name, l.Name, StringComparison.OrdinalIgnoreCase) ||
                                          string.Equals((x.Url ?? "").TrimEnd('/'), (l.Url ?? "").TrimEnd('/'), StringComparison.OrdinalIgnoreCase)))
                        s.Links.Add(l);
                MergeTemplates(s.Templates,d.Templates);
                s.Settings.DefaultsVersion = d.Version;
                // Изменённый извне список не перезаписываем до решения пользователя (вопрос в главном окне).
                if (!readOnly && ChangedOutside == null) s.Save();
            }
            return s;
        }

        internal static string TemplateName(string name) {
            switch((name ?? "").Trim().ToLowerInvariant()) {
                case "steam": case "steam (веб)": return "Steam Community";
                case "google / youtube / gmail": return "Google";
                case "вконтакте (vk id)": return "ВКонтакте";
                case "билайн (личный кабинет)": return "Билайн";
                case "discord (веб)": return "Discord";
                case "epic games (веб)": return "Epic Games Launcher";
                case "battle.net (веб)": return "Battle.net";
                case "ea (веб)": return "EA app";
                case "ubisoft (веб)": return "Ubisoft Connect";
                case "telegram web": return "Telegram";
                default: return (name ?? "").Trim();
            }
        }
        internal static void MergeTemplates(List<LoginTemplate> saved,IEnumerable<LoginTemplate> additions) {
            var merged=new List<LoginTemplate>();
            foreach(var item in saved.OrderByDescending(x=>x.Group=="Мои").Concat(additions)) {
                string key=TemplateName(item.Name);
                var old=merged.FirstOrDefault(x=>string.Equals(TemplateName(x.Name),key,StringComparison.OrdinalIgnoreCase));
                if(old==null) { if(item.Group!="Мои") item.Name=key; merged.Add(item); continue; }
                if(old.Group=="Мои") continue;
                bool oldApp=old.Kind=="app", newApp=item.Kind=="app";
                if(oldApp && !newApp) { old.AppTarget=old.Target; old.Target=item.Target; old.Kind="both"; }
                else if(!oldApp && newApp) { if(string.IsNullOrEmpty(old.AppTarget)) old.AppTarget=item.Target; old.Kind="both"; }
                else if(item.Kind=="both") old.Kind="both";
                if(string.IsNullOrEmpty(old.AppTarget)) old.AppTarget=item.AppTarget;
                if(string.IsNullOrEmpty(old.LoginUrl)) old.LoginUrl=item.LoginUrl;
                if(string.IsNullOrEmpty(old.LoginProfile)) old.LoginProfile=item.LoginProfile;
                if(string.IsNullOrEmpty(old.Category)) old.Category=item.Category;
            }
            saved.Clear(); saved.AddRange(merged.OrderBy(x=>x.Name,StringComparer.CurrentCultureIgnoreCase));
        }

        // Хэш apps.json, если при загрузке он не совпал с отпечатком WinUp (файл изменён вне программы), иначе null.
        public static string ChangedOutside;

        public void Save()
        {
            Paths.AtomicWrite(Paths.AppsFile, new UTF8Encoding(false).GetBytes(Json.Write(this, true)));
            // Запоминаем «своё» состояние списка: изменение извне будет заметно при следующем запуске.
            try { Integrity.SetApps(Integrity.HashFile(Paths.AppsFile)); } catch { }
            // Резерв списка — только когда есть база паролей (до этого папка резерва ещё не выбрана).
            // Раньше проверялся только старый vault.dat: после перехода на vault.kdbx копии apps.json не писались вовсе.
            if (System.IO.File.Exists(Paths.KdbxFile) || System.IO.File.Exists(Paths.VaultFile)) Backup.Copy(Paths.AppsFile, "apps", ".json", Settings);
        }

        public static string NewId() { return Guid.NewGuid().ToString("N").Substring(0, 8); }
    }

    // data\integrity.json — наблюдение «доверяем при первом использовании» за файлами, которые WinUp
    // не может защитить криптографией (apps.json, внешний keepassxc-cli). Сам файл не подписан секретом,
    // поэтому это детектор случайных и несофистицированных подмен, а не гарантия. Свои записи WinUp
    // обновляет сам; предупреждение показывается только при изменении вне работающего приложения.
    public class IntegrityData
    {
        public string Apps { get; set; }
        public string Cli { get; set; }
        public string CliPath { get; set; }
    }

    // Отпечатки файлов, которые WinUp пишет сам (apps.json). Хранятся в реестре пользователя, отдельно для
    // каждой папки WinUp: отпечаток рядом с файлом (data\integrity.json) ничего не защищал — кто правит
    // apps.json, поправил бы и его. Старый integrity.json читается один раз, при переходе.
    public static class Integrity
    {
        static string LegacyFile { get { return Path.Combine(Paths.Data, "integrity.json"); } }
        static string Key { get { return @"Software\WinUp\Integrity\" + Program.FolderHash(Paths.Root); } }

        public static IntegrityData Load()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(Key))
                    if (k != null)
                        return new IntegrityData { Apps = k.GetValue("Apps") as string, Cli = k.GetValue("Cli") as string, CliPath = k.GetValue("CliPath") as string };
                // Переход с прежних версий (или первый запуск этой папки на этом ПК после переноса).
                if (System.IO.File.Exists(LegacyFile))
                {
                    var d = Json.Read<IntegrityData>(System.IO.File.ReadAllText(LegacyFile, Encoding.UTF8));
                    if (d != null) { Save(d); return d; }
                }
            }
            catch { }
            return new IntegrityData();
        }

        static void Save(IntegrityData d)
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(Key))
                {
                    k.SetValue("Apps", d.Apps ?? "");
                    k.SetValue("Cli", d.Cli ?? "");
                    k.SetValue("CliPath", d.CliPath ?? "");
                    k.SetValue("Folder", Paths.Root);
                }
                // Прежний файл больше не источник истины — убираем, чтобы не вводил в заблуждение.
                if (System.IO.File.Exists(LegacyFile)) System.IO.File.Delete(LegacyFile);
            }
            catch { }
        }

        public static string HashFile(string path)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            using (var f = System.IO.File.OpenRead(path))
                return BitConverter.ToString(sha.ComputeHash(f)).Replace("-", "");
        }

        public static string AppsHash() { return System.IO.File.Exists(Paths.AppsFile) ? HashFile(Paths.AppsFile) : null; }
        public static string GetApps() { return Load().Apps; }
        public static void SetApps(string hash) { var d = Load(); d.Apps = hash; Save(d); }
        public static string GetCli() { return Load().Cli; }
        public static void SetCli(string hash, string path) { var d = Load(); d.Cli = hash; d.CliPath = path; Save(d); }
    }

    public class DefaultsData
    {
        public int Version { get; set; }
        public List<LinkItem> Links { get; set; }
        public List<LoginTemplate> Templates { get; set; }
    }

    // Встроенные в exe шаблоны входа и ссылки на скачивание (src\defaults.json).
    static class Defaults
    {
        public static DefaultsData Load()
        {
            using (var s = typeof(Defaults).Assembly.GetManifestResourceStream("defaults.json"))
            {
                DefaultsData d = null;
                if (s != null) using (var r = new StreamReader(s, Encoding.UTF8)) d = Json.Read<DefaultsData>(r.ReadToEnd());
                d = d ?? new DefaultsData();
                if (d.Links == null) d.Links = new List<LinkItem>();
                if (d.Templates == null) d.Templates = new List<LoginTemplate>();
                return d;
            }
        }
    }

    // Копия WinUp для другого человека: exe, пустая apps, шаблоны и ссылки — без программ, паролей и личных настроек.
    static class Share
    {
        public static string Make(AppStore store, string parent, string exePath)
        {
            var target = Path.Combine(parent, "WinUp");
            for (int n = 2; Directory.Exists(target) && Directory.EnumerateFileSystemEntries(target).Any(); n++) target = Path.Combine(parent, "WinUp (" + n + ")");
            var full = Path.GetFullPath(target);
            if (full.StartsWith(Paths.RootPrefix, StringComparison.OrdinalIgnoreCase) || string.Equals(full, Paths.Root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Выберите папку вне текущего WinUp.");
            Directory.CreateDirectory(Path.Combine(target, "apps"));
            Directory.CreateDirectory(Path.Combine(target, "data"));
            System.IO.File.Copy(exePath, Path.Combine(target, "WinUp.exe"));
            // Ядро шифрования вшито в WinUp.exe — отдельный KeePassLib.dll получателю не нужен;
            // THIRD-PARTY.md — лицензия GPL ядра, она обязана ехать вместе с библиотекой (берётся из exe, если рядом нет).
            foreach (var name in Paths.Bundled) Paths.CopyBundled(name, Path.Combine(target, name));
            // Шаблоны группы «Мои» — личные (пути, заметки владельца): в копию для другого человека не идут.
            var copy = new AppStore { Links = store.Links, Templates = store.Templates.Where(t => t.Group != "Мои").ToList() };
            copy.Settings.DefaultsVersion = store.Settings.DefaultsVersion;
            copy.Settings.BackupDir = ""; // у получателя — его «Документы» (см. AppStore.Load)
            Paths.AtomicWrite(Path.Combine(target, "data", "apps.json"), new UTF8Encoding(false).GetBytes(Json.Write(copy, true)));
            return target;
        }
    }

    static class Backup
    {
        public static string LastError;

        public static void Copy(string src, string prefix, string ext, Settings s)
        {
            try
            {
                using (Paths.HoldWriteDirectory(s.BackupDir))
                {
                var dst = Path.Combine(s.BackupDir, prefix + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss-fff") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ext);
                Export.CopyEncryptedDatabase(src, dst);
                // Паттерн "vault-*.dat" из-за 8.3-имён захватывает и чужие "vault-*.data" —
                // оставляем только точное совпадение расширения с расширением бэкапа.
                var outdated = Directory.GetFiles(s.BackupDir, prefix + "-*" + ext)
                    .Where(f => !string.Equals(f, dst, StringComparison.OrdinalIgnoreCase) && IsBackupName(f, prefix, ext))
                    .OrderByDescending(f => f).Skip(Math.Max(0, s.BackupKeep - 1));
                foreach (var old in outdated)
                {
                    // Одна залоченная старая копия не должна портить статус только что сделанной записи.
                    try { System.IO.File.Delete(old); }
                    catch { }
                }
                }
                LastError = null;
            }
            catch (Exception e) { LastError = e.Message; }
        }

        internal static bool IsBackupName(string file, string prefix, string extension)
        {
            if (!string.Equals(Path.GetExtension(file), extension, StringComparison.OrdinalIgnoreCase)) return false;
            var match = Regex.Match(Path.GetFileNameWithoutExtension(file), "^" + Regex.Escape(prefix) + @"-(?<date>\d{8}-\d{6}-\d{3})(?:-[0-9a-fA-F]{8})?$");
            DateTime date;
            return match.Success && DateTime.TryParseExact(match.Groups["date"].Value, "yyyyMMdd-HHmmss-fff", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out date);
        }
    }

    // Синхронизируемые облачные папки: копии базы в них уходят в облако (зашифрованными), а удалённые файлы ещё
    // долго лежат в корзине и истории версий облака — после смены пароля старые копии оттуда так просто не стереть.
    static class CloudFolder
    {
        // Название облака, если папка внутри синхронизируемой; иначе null.
        public static string Of(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            string full;
            try { full = Path.GetFullPath(path).TrimEnd('\\') + "\\"; }
            catch { return null; }
            foreach (var v in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
                if (Under(full, Environment.GetEnvironmentVariable(v))) return "OneDrive";
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\OneDrive\Accounts"))
                    if (k != null)
                        foreach (var a in k.GetSubKeyNames())
                            using (var ak = k.OpenSubKey(a))
                                if (ak != null && Under(full, ak.GetValue("UserFolder") as string)) return "OneDrive";
            }
            catch { }
            foreach (var info in new[] { Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) })
                try
                {
                    var f = Path.Combine(info, "Dropbox", "info.json");
                    if (File.Exists(f))
                        foreach (Match m in Regex.Matches(File.ReadAllText(f), "\"path\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\""))
                            if (Under(full, Regex.Unescape(m.Groups[1].Value))) return "Dropbox";
                }
                catch { }
            var lower = full.ToLowerInvariant();
            if (lower.Contains("\\dropbox\\")) return "Dropbox";
            if (lower.Contains("\\google drive\\") || lower.Contains("\\my drive\\") || lower.Contains("\\мой диск\\")) return "Google Диск";
            if (lower.Contains("\\yandexdisk") || lower.Contains("\\яндекс.диск") || lower.Contains("\\yandex.disk")) return "Яндекс Диск";
            if (lower.Contains("\\iclouddrive\\")) return "iCloud";
            try
            {
                var root = Path.GetPathRoot(full);
                if (!string.IsNullOrEmpty(root) && root.Length <= 3 && new DriveInfo(root).VolumeLabel == "Google Drive") return "Google Диск";
            }
            catch { }
            return null;
        }

        static bool Under(string full, string folder)
        {
            if (string.IsNullOrWhiteSpace(folder)) return false;
            try { return full.StartsWith(Path.GetFullPath(folder).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }

        // Предупреждение для журнала и окон; null — папка не в облаке.
        public static string Warning(string path, string what)
        {
            var c = Of(path);
            if (c == null) return null;
            return what + " в " + c + ": копии базы уходят в облако (зашифрованными). Удалённые копии ещё долго хранятся в корзине и истории версий " +
                   c + " — после смены пароля базы очистите их там вручную, иначе их откроет прежний пароль.";
        }
    }

    static class Json
    {
        static JavaScriptSerializer Serializer() { return new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024, RecursionLimit = 64 }; }

        public static T Read<T>(string text) { return Serializer().Deserialize<T>(text); }

        public static string Write(object o, bool pretty)
        {
            var s = Serializer().Serialize(o);
            // Сериализатор пишет не-ASCII как \uXXXX — возвращаем читаемый вид.
            // Замена только для эскейпов самого сериализатора: \u, перед которым стоит
            // не-бэкслэш и чётное число бэкслэшей. Экранированные данные вида \\uXXXX
            // (пользовательская обратная косая черта + буквы u0444) не трогаются —
            // иначе после чтения файл не разбирается (ревью п.4.2).
            s = Regex.Replace(s, @"(?<=[^\\](?:\\\\)*)\\u([0-9a-fA-F]{4})", m =>
            {
                int c = Convert.ToInt32(m.Groups[1].Value, 16);
                return c >= 0x80 ? ((char)c).ToString() : m.Value;
            });
            return pretty ? Indent(s) : s;
        }

        static string Indent(string json)
        {
            var sb = new StringBuilder();
            int ind = 0; bool q = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (q)
                {
                    sb.Append(c);
                    if (c == '\\' && i + 1 < json.Length) sb.Append(json[++i]);
                    else if (c == '"') q = false;
                    continue;
                }
                switch (c)
                {
                    case '"': q = true; sb.Append(c); break;
                    case '{':
                    case '[':
                        if (i + 1 < json.Length && (json[i + 1] == '}' || json[i + 1] == ']')) { sb.Append(c).Append(json[++i]); break; }
                        sb.Append(c).Append("\r\n").Append(' ', ++ind * 2); break;
                    case '}':
                    case ']': sb.Append("\r\n").Append(' ', --ind * 2).Append(c); break;
                    case ',': sb.Append(c).Append("\r\n").Append(' ', ind * 2); break;
                    case ':': sb.Append(": "); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }
    }

    // Определение типа установщика по сигнатурам внутри файла и подбор ключей тихой установки.
    static class Detect
    {
        public const string Inno = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-";

        public static void Fill(AppItem a)
        {
            string args, note;
            Guess(Paths.Full(a.File), out args, out note);
            a.Args = args; a.Note = note;
        }

        // true — файл похож на установщик (известный тип или MSI).
        public static bool Guess(string path, out string args, out string note)
        {
            if (path.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)) { args = "/qn /norestart"; note = "MSI"; return true; }
            string text;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var buf = new byte[(int)Math.Min(fs.Length, 8 * 1024 * 1024)];
                    int n = 0, r;
                    while (n < buf.Length && (r = fs.Read(buf, n, buf.Length - n)) > 0) n += r;
                    text = Encoding.GetEncoding(28591).GetString(buf, 0, n);
                }
            }
            catch (Exception e) { args = ""; note = "не удалось прочитать: " + e.Message; return false; }

            if (text.Contains("Inno Setup")) { args = Inno; note = "Inno Setup"; return true; }
            // Установщик 7-Zip — собственный (7zipInstall), не NSIS; тихий режим — /S.
            if (text.Contains("7zipInstall")) { args = "/S"; note = "7-Zip"; return true; }
            // Свои установщики, которые по сигнатурам не узнать, — по свойствам файла.
            string product = "";
            try { product = (System.Diagnostics.FileVersionInfo.GetVersionInfo(path).ProductName ?? "").Trim(); } catch { }
            if (product == "WinRAR") { args = "/S"; note = "WinRAR"; return true; }
            if (product == "Google Installer" && text.Contains("GoogleUpdate")) { args = "/silent /install"; note = "Google (веб-загрузчик, нужен интернет)"; return true; }
            if (text.Contains("Nullsoft")) { args = "/S"; note = "NSIS"; return true; }
            if (text.Contains("Velopack") || text.Contains("Squirrel")) { args = "--silent"; note = "Squirrel/Velopack"; return true; }
            if (text.Contains("Advanced Installer")) { args = "/exenoui /qn /norestart"; note = "Advanced Installer"; return true; }
            if (text.Contains("InstallShield")) { args = "/s /v\"/qn /norestart\""; note = "InstallShield"; return true; }
            args = ""; note = "тип не определён — установка вручную; если программа портативная, смените тип";
            return false;
        }
    }

    // Удаление в Корзину (SHFileOperation, FOF_ALLOWUNDO): перенесённое в apps\ можно передумать и вернуть.
    static class Recycle
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SHFILEOPSTRUCT
        {
            public IntPtr hwnd;
            public uint wFunc;
            public string pFrom;
            public string pTo;
            public ushort fFlags;
            public bool fAnyOperationsAborted;
            public IntPtr hNameMappings;
            public string lpszProgressTitle;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SHFileOperation(ref SHFILEOPSTRUCT op);

        // Папки-контейнеры (Загрузки, Рабочий стол, Документы, Program Files, корень диска...)
        // не удаляются даже с галочкой «удалить источник»: рядом с программой там лежат чужие файлы.
        public static bool IsProtectedFolder(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path)) return true;
                var p = Path.GetFullPath(path).TrimEnd('\\');
                if (p.Length <= 3) return true; // корень диска
                // На сетевых путях Корзины нет — удалять корень шары (\\server\share) и сам сервер (\\server) нельзя.
                if (p.StartsWith("\\\\", StringComparison.Ordinal))
                {
                    var root = Path.GetPathRoot(p); // для "\\server\share\sub" вернёт "\\server\share"
                    if (!string.IsNullOrEmpty(root) && string.Equals(root.TrimEnd('\\'), p, StringComparison.OrdinalIgnoreCase))
                        return true;
                    if (p.IndexOf('\\', 2) < 0) return true; // "\\server" без имени шары
                }
                var shell = new List<string>
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
                    InstallerSearch.Downloads(),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                };
                foreach (var s in shell)
                    if (!string.IsNullOrEmpty(s) && string.Equals(Path.GetFullPath(s).TrimEnd('\\'), p, StringComparison.OrdinalIgnoreCase))
                        return true;
                return false;
            }
            catch { return true; }
        }

        // true — только если SHFileOperation вернул 0 и операция не была прервана (fAnyOperationsAborted).
        public static bool Delete(string path)
        {
            try
            {
                var op = new SHFILEOPSTRUCT
                {
                    wFunc = 3, // FO_DELETE
                    pFrom = path + "\0\0",
                    fFlags = (ushort)(0x40 | 0x10 | 0x4 | 0x400) // ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
                };
                return SHFileOperation(ref op) == 0 && !op.fAnyOperationsAborted;
            }
            catch { return false; }
        }
    }
}

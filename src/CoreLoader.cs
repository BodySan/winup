using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace WinUp
{
    // Embedded core is the baseline. External cores must be newer and signed
    // by the KeePass publisher. Trust is never taken from a writable registry hash.
    public static class CoreLoader
    {
        public const string FileName = "KeePassLib.dll";
        public const string Publisher = "Open Source Developer, Dominik Reichl";
        const string TrustKey = @"Software\WinUp\TrustedCore";

        public static string CoreDir { get { return Path.Combine(Paths.Data, "core"); } }
        public static string CoreFile { get { return Path.Combine(CoreDir, FileName); } }

        public static string Source = "";   // откуда загружено — для журнала и «О программе»
        public static string Note;          // почему обновлённое ядро не взято / что сделано при запуске

        static Assembly loaded;
        static readonly object sync = new object();

        public static Assembly Resolve()
        {
            lock (sync)
            {
                if (loaded == null) loaded = Load();
                return loaded;
            }
        }

        // Прежние версии клали KeePassLib.dll рядом с exe. Такой файл Windows загружает сама, раньше обработчика
        // AssemblyResolve, — и вшитое ядро никогда бы не использовалось. Вызывается до первого обращения к ядру.
        public static void MigrateLegacy()
        {
            var legacy = Path.Combine(Paths.Root, FileName);
            if (!File.Exists(legacy)) return;
            try
            {
                var emb = Embedded();
                var legacyVer = AssemblyName.GetAssemblyName(legacy).Version;
                var embVer = emb == null ? null : VersionOf(emb);
                if (embVer == null) return; // сборка без вшитого ядра — файл рядом с exe нужен
                if (legacyVer > embVer)
                {
                    Directory.CreateDirectory(CoreDir);
                    if (!File.Exists(CoreFile)) File.Copy(legacy, CoreFile);
                    Note = "KeePassLib.dll " + V(legacyVer) + " перенесён из папки программы в data\\core.";
                }
                else Note = "KeePassLib.dll рядом с WinUp.exe больше не нужен (ядро вшито в программу) — удалён.";
                File.Delete(legacy);
            }
            catch (Exception ex) { Note = "Не удалось убрать KeePassLib.dll рядом с WinUp.exe: " + ex.Message; }
        }

        static Assembly Load()
        {
            byte[] emb = Embedded();
            Version embVer = emb == null ? null : VersionOf(emb);
            try
            {
                if (File.Exists(CoreFile))
                {
                    Version ver;
                    var bytes = ReadVerifiedCore(CoreFile, out ver);
                    if (embVer != null && ver <= embVer)
                        AddNote("Крипто-ядро в data\\core (" + V(ver) + ") не новее вшитого — используется вшитое.");
                    else
                    {
                        Source = "обновлённое, data\\core";
                        return Assembly.Load(bytes);
                    }
                }
            }
            catch (Exception ex) { AddNote("Крипто-ядро в data\\core не прочитано (" + ex.Message + ") — используется вшитое."); }
            if (emb != null) { Source = "вшитое в WinUp.exe"; return Assembly.Load(emb); }
            // Сборка без вшитого ядра (собрана старым способом): файл рядом с exe.
            var legacy = Path.Combine(Paths.Root, FileName);
            if (File.Exists(legacy))
            {
                Version version;
                var bytes = ReadVerifiedCore(legacy, out version);
                Source = "подписанное ядро рядом с WinUp.exe";
                return Assembly.Load(bytes);
            }
            return null;
        }

        public static byte[] ReadVerifiedCore(string path, out Version version)
        {
            version = null;
            // Hold the file against writing/replacement until signature verification,
            // metadata and the exact bytes for Assembly.Load have all been read.
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (file.Length <= 0 || file.Length > 32 * 1024 * 1024) throw new InvalidDataException("Неверный размер крипто-ядра.");
                if (!Signature.SignedByName(path, Publisher))
                    throw new InvalidDataException("Крипто-ядро не имеет действительной подписи издателя KeePass.");
                var identity = AssemblyName.GetAssemblyName(path);
                if (identity.Name != "KeePass" && identity.Name != "KeePassLib") throw new InvalidDataException("Неверное крипто-ядро.");
                var bytes = new byte[(int)file.Length];
                int offset = 0;
                while (offset < bytes.Length)
                {
                    int read = file.Read(bytes, offset, bytes.Length - offset);
                    if (read == 0) throw new EndOfStreamException();
                    offset += read;
                }
                version = identity.Version;
                return bytes;
            }
        }

        static void AddNote(string s) { Note = string.IsNullOrEmpty(Note) ? s : Note + " " + s; }

        public static byte[] Embedded()
        {
            using (var s = typeof(CoreLoader).Assembly.GetManifestResourceStream(FileName))
            {
                if (s == null) return null;
                var b = new byte[s.Length];
                int n = 0, r;
                while (n < b.Length && (r = s.Read(b, n, b.Length - n)) > 0) n += r;
                return b;
            }
        }

        // Версия сборки из байтов без загрузки в процесс: через временный файл и метаданные.
        static Version VersionOf(byte[] bytes)
        {
            var tmp = Path.GetTempFileName();
            try { File.WriteAllBytes(tmp, bytes); return AssemblyName.GetAssemblyName(tmp).Version; }
            finally { try { File.Delete(tmp); } catch { } }
        }

        public static string Sha256(byte[] b)
        {
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(b)).Replace("-", "");
        }

        static string V(Version v) { return v.Major + "." + v.Minor + (v.Build > 0 ? "." + v.Build : ""); }

        // Папки при запуске: data\core с пояснением, чтобы пустая папка не вызывала вопросов.
        public static void EnsureDir()
        {
            try
            {
                Directory.CreateDirectory(CoreDir);
                var readme = Path.Combine(CoreDir, "README.txt");
                if (!File.Exists(readme))
                    File.WriteAllText(readme,
                        "Сюда WinUp кладёт обновлённое крипто-ядро KeePassLib.dll (Меню → О программе → Проверить обновление крипто-ядра).\r\n" +
                        "Пока папка пустая, используется ядро, вшитое в WinUp.exe. Папку можно очистить — WinUp вернётся к вшитому ядру.\r\n",
                        new System.Text.UTF8Encoding(true));
            }
            catch { }
        }
    }
}

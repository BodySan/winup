using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using KeePassLib;
using KeePassLib.Cryptography.KeyDerivation;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Security;

namespace WinUp
{
    public enum StoreResult { Ok, Wrong, Wiped }

    // Хранилище WinUp на ядре KeePassLib (KeePass 2.6x, GPL v2+):
    //   data\vault.kdbx    — база KDBX 4, Argon2 64 МБ / 8 итераций / 2 потока (калибровка ~0.7 с).
    //                        Стандартный файл: открывается KeePassXC, KeePassDX, Strongbox.
    //   data\recovery.kdbx — копия базы, зашифрованная кодом восстановления; обновляется при каждом сохранении,
    //                        пока код развёрнут в памяти (обёртка кода в tab.dat закрыта кеем пароля базы).
    //   data\tab.dat       — локальный сайдкар: счётчик попыток пароля базы, обёртка кода восстановления.
    //                        Файл не шифруется: атакующий с копией папки может его стереть/подменить —
    //                        защита от подбора только через интерфейс WinUp.
    // Уничтожение после N неверных попыток (по решению владельца): счётчик в tab.dat,
    // исчерпание — перезапись и удаление vault.kdbx, recovery.kdbx и tab.dat.
    public sealed partial class KdbxStore
    {
        public const int P2Max = 7, PinMax = 5;
        const int RcIters = 600000, PinIters = 600000;
        const string OtpGroupName = "Коды 2FA";

        // Версия крипто-ядра читается из загруженной сборки KeePassLib.dll, а не хранится строкой:
        // после замены DLL на более свежую «О программе» и журнал показывают фактическую версию.
        // Обращение к типу ядра вынесено в отдельный метод: FileLoadException/FileNotFoundException
        // при его JIT бросается в вызов и ловится здесь (JIT-изоляция).
        public static string LibVersion()
        {
            try { return LibVersionCore(); }
            catch { return "неизвестна"; }
        }

        static string LibVersionCore()
        {
            var v = typeof(PwDatabase).Assembly.GetName().Version;
            return v.Major + "." + v.Minor + (v.Build > 0 ? "." + v.Build : "");
        }

        PwDatabase db;
        readonly SecretText masterPassword = new SecretText();
        readonly SecretBytes keyFile = new SecretBytes();
        readonly SecretText recoveryCode = new SecretText();
        string p2 { set { masterPassword.Set(value); } }
        byte[] kf { set { keyFile.Set(value); } }
        string rc { set { recoveryCode.Set(value); } }
        T UseMaster<T>(Func<string, byte[], T> action)
        {
            var bytes = keyFile.Read();
            var pin = bytes == null ? default(GCHandle) : GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try { return masterPassword.Use(pw => action(pw, bytes)); }
            finally { if (bytes != null) Array.Clear(bytes, 0, bytes.Length); if (pin.IsAllocated) pin.Free(); }
        }
        void LoadRecoveryCode()
        {
            var code = UnwrapRc();
            try {
                recoveryCode.Set(code);
                if (hasRc && string.IsNullOrEmpty(code)) { RecoveryNeedsRepair = true; hasRc = false; rcWrap = new byte[0]; }
            }
            finally { Secure.Wipe(code); }
        }
        byte[] p2Salt, rcWrap;
        int p2Fails;
        bool kfRequired, hasRc;
        // tab.dat не было (база восстановлена из резерва одна, перенесена без сайдкара, сохранена KeePassXC):
        // нужен ли ключ-файл — неизвестно, поэтому при входе он необязателен; после входа сайдкар пишется заново.
        bool kfUnknown, tabRecreated;

        public List<LoginEntry> Entries = new List<LoginEntry>();
        public List<OtpEntry> Otp = new List<OtpEntry>();
        public bool KeyFileRequired { get { return kfRequired; } }
        public bool HasRecovery { get { return hasRc; } }
        public bool RecoveryNeedsRepair { get; private set; }
        // Вход создал tab.dat заново: счётчик попыток с нуля, код восстановления этой копии неизвестен.
        public bool TabRecreated { get { return tabRecreated; } }

        KdbxStore() { }

        static string KdbxPath { get { return Path.Combine(Paths.Data, "vault.kdbx"); } }
        static string RecoveryPath { get { return Path.Combine(Paths.Data, "recovery.kdbx"); } }
        static string TabPath { get { return Path.Combine(Paths.Data, "tab.dat"); } }
        static string LegacyPath { get { return Paths.VaultFile; } }
        // Старая база после переноса в kdbx переименовывается в vault-legacy.dat (см. MigrateFromLegacy).
        static string LegacyArchivePath { get { return Path.Combine(Paths.Data, "vault-legacy.dat"); } }

        public static string KdbxFile { get { return KdbxPath; } }
        public static string RecoveryFile { get { return RecoveryPath; } }
        public static string TabFile { get { return TabPath; } }
        internal static List<string> PurgeLocalOldCopies()
        {
            var errors = new List<string>();
            foreach (var path in new[] { KdbxPath, RecoveryPath, TabPath, LegacyPath })
                foreach (var copy in new[] { path + ".bak" }.Concat(Paths.AtomicRemnants(path)))
                {
                    string error;
                    if (!Secure.WipeFile(copy, out error)) errors.Add(Path.GetFileName(copy) + ": " + error);
                }
            return errors;
        }

        // Осталось попыток пароля базы по счётчику сайдкара.
        public static int AttemptsLeft()
        {
            try { return P2Max - ReadTab().p2Fails; }
            catch { return P2Max; }
        }

        // Подтверждение пароля базы (смена пароля, экспорт): открытие копии базы.
        public bool VerifyDbPassword(string pw)
        {
            var d = new PwDatabase();
            var bytes = keyFile.Read();
            try { KdbxSafety.OpenDatabase(d, KdbxPath, MakeKey(pw, bytes), NullLog); return true; }
            catch (InvalidCompositeKeyException) { return false; }
            catch { return false; }
            finally { d.Close(); if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
        }

        public static bool Exists { get { return File.Exists(KdbxPath); } }
        public static bool RecoveryExists { get { return File.Exists(RecoveryPath); } }
        public static bool LegacyExists { get { return File.Exists(LegacyPath); } }

        // База требует ключ-файл (флаг в сайдкаре).
        public static bool FileHasKeyFile()
        {
            try { return ReadTab().kfRequired; }
            catch { return false; }
        }

        // Неизвестно, закрыта ли база ключ-файлом (сайдкара не было): поле ключ-файла при входе необязательное.
        public static bool KeyFileOptional()
        {
            try { return ReadTab().kfUnknown; }
            catch { return false; }
        }

        public static bool FileHasRecovery()
        {
            try { return ReadTab().hasRc; }
            catch { return false; }
        }

        // Доступен ли файл базы для записи: счётчики попыток и уничтожение требуют записи (fail-closed).
        public static bool FileWritable()
        {
            try
            {
                using (File.Open(KdbxPath, FileMode.Open, FileAccess.ReadWrite)) { }
                // Сайдкара может не быть (база восстановлена из резерва одна) — тогда он будет создан
                // при первом входе; проверяем только существующий файл, побочно его не создаём.
                if (File.Exists(TabPath)) using (File.Open(TabPath, FileMode.Open, FileAccess.ReadWrite)) { }
                return true;
            }
            catch { return false; }
        }

        // ---------------- tab.dat ----------------

        // WUT2 (пароль вкладки убран): "WUT2" | p2Fails(4) | kfFlag(1) | hasRc(1) | rcWrapLen(2) | p2Salt(16) | rcWrap(...)
        // WUT1 (до 1.6.0, два пароля): "WUT1" | p1Fails(4) | p2Fails(4) | kfFlag(1) | hasRc(1) | rcWrapLen(2) |
        //     p1Salt(16) | p1Hash(32) | p2Salt(16) | rcWrap(...) — читаем поля пароля базы, поля пароля 1 игнорируем.
        static readonly byte[] TabMagic = Encoding.ASCII.GetBytes("WUT2");
        static readonly byte[] TabMagicV1 = Encoding.ASCII.GetBytes("WUT1");

        byte[] TabBytes()
        {
            var b = new byte[28 + (rcWrap == null ? 0 : rcWrap.Length)];
            Buffer.BlockCopy(TabMagic, 0, b, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(p2Fails), 0, b, 4, 4);
            b[8] = (byte)(kfRequired ? 1 : kfUnknown ? 2 : 0); // 2 — «неизвестно» (сайдкар создан без входа)
            b[9] = (byte)(hasRc ? 1 : 0);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)(rcWrap == null ? 0 : rcWrap.Length)), 0, b, 10, 2);
            if (p2Salt != null) Buffer.BlockCopy(p2Salt, 0, b, 12, 16);
            if (rcWrap != null) Buffer.BlockCopy(rcWrap, 0, b, 28, rcWrap.Length);
            return b;
        }
        void WriteTab() { Paths.AtomicWrite(TabPath, TabBytes()); }

        static KdbxStore ReadTab()
        {
            // Сайдкара нет — база пришла одна (резерв vault-*.kdbx, перенос, KeePassXC). Раньше вход падал
            // на FileNotFoundException, а подсказка «восстановите vault-*.kdbx из резерва» вела в тупик.
            // Счётчик начинается с нуля: файл без защиты, атакующий с копией папки и так подбирает офлайн.
            if (!File.Exists(TabPath))
                return new KdbxStore { p2Salt = Vault.Random(16), rcWrap = new byte[0], kfUnknown = true };
            var b = SafeStorage.ReadBounded(TabPath, 80 + ushort.MaxValue);
            if (b.Length < 28) throw new InvalidDataException("Файл замка вкладки повреждён.");
            bool v1 = b[0] == TabMagicV1[0] && b[1] == TabMagicV1[1] && b[2] == TabMagicV1[2] && b[3] == TabMagicV1[3];
            bool v2 = b[0] == TabMagic[0] && b[1] == TabMagic[1] && b[2] == TabMagic[2] && b[3] == TabMagic[3];
            if (!v1 && !v2) throw new InvalidDataException("Файл замка вкладки повреждён.");
            if (v1 && b.Length < 80) throw new InvalidDataException("Файл замка вкладки повреждён.");
            var s = new KdbxStore();
            if (v1)
            {
                // Старый формат: p2Fails(4)@8, kf@12, hasRc@13, rcLen@14, p2Salt@64, rcWrap@80.
                // Счётчик попыток пароля 1 не переносится: попыток пароля 1 больше нет.
                var rcLen1 = BitConverter.ToUInt16(b, 14);
                if (rcLen1 != b.Length - 80) throw new InvalidDataException("Файл замка вкладки повреждён.");
                s.p2Fails = Math.Max(0, BitConverter.ToInt32(b, 8));
                s.kfRequired = b[12] == 1;
                s.hasRc = b[13] == 1;
                s.p2Salt = Slice(b, 64, 16);
                s.rcWrap = rcLen1 > 0 ? Slice(b, 80, rcLen1) : new byte[0];
            }
            else
            {
                var rcLen = BitConverter.ToUInt16(b, 10);
                if (rcLen != b.Length - 28) throw new InvalidDataException("Файл замка вкладки повреждён.");
                s.p2Fails = Math.Max(0, BitConverter.ToInt32(b, 4));
                s.kfRequired = b[8] == 1;
                s.kfUnknown = b[8] == 2;
                s.hasRc = b[9] == 1;
                s.p2Salt = Slice(b, 12, 16);
                s.rcWrap = rcLen > 0 ? Slice(b, 28, rcLen) : new byte[0];
            }
            if (s.p2Fails >= P2Max) throw new InvalidDataException("Счётчик попыток в замке вкладки повреждён.");
            return s;
        }

        // Ошибки последнего уничтожения («vault.kdbx: <причина>») — MainForm показывает их пользователю.
        public static readonly List<string> WipeErrors = new List<string>();

        // Перезаписать секретные файлы случайными байтами и удалить (уничтожение по исчерпанию попыток).
        // Кроме текущей базы затираем остатки AtomicWrite (.bak/.tmp сайдкара) и легаси-файлы старого
        // формата (vault.dat и архив vault-legacy.dat) — в них лежат те же секреты.
        static void WipeFiles()
        {
            WipeErrors.Clear();
            var files = new[] { KdbxPath, KdbxPath + ".bak", RecoveryPath, RecoveryPath + ".bak", TabPath, TabPath + ".bak", TabPath + ".tmp",
                LegacyPath, LegacyPath + ".bak", LegacyPath + ".tmp", LegacyArchivePath };
            foreach (var p in files.Concat(new[] { KdbxPath, RecoveryPath, TabPath, LegacyPath }.SelectMany(Paths.AtomicRemnants)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string error;
                if (!Secure.WipeFile(p, out error)) WipeErrors.Add(Path.GetFileName(p) + ": " + error);
            }
            // Ключ базы под Windows Hello (вне папки WinUp) уничтожается вместе с базой.
            WindowsHello.Disable();
        }

        static byte[] Slice(byte[] b, int off, int len)
        {
            var r = new byte[len];
            Buffer.BlockCopy(b, off, r, 0, len);
            return r;
        }

        // Своя копия строки вместо интернированного экземпляра: Lock() затирает строку на месте,
        // и общий с литералом экземпляр испортил бы остальные ссылки (R-8 из ревью).
        static string Uninterned(string s)
        {
            if (s == null) return null;
            return new string(s.ToCharArray());
        }

        // ---------------- пароль базы: kdbx ----------------

        static CompositeKey MakeKey(string password, byte[] keyFile)
        {
            var k = new CompositeKey();
            var passwordBytes = Encoding.UTF8.GetBytes(password ?? "");
            var pin = GCHandle.Alloc(passwordBytes, GCHandleType.Pinned);
            try { k.AddUserKey(new KcpPassword(passwordBytes, false)); }
            finally { Array.Clear(passwordBytes, 0, passwordBytes.Length); pin.Free(); }
            if (keyFile != null && keyFile.Length > 0)
            {
                // KeePass requires a path. Keep its temporary copy off shared/removable
                // data\ and restrict the staging directory to this Windows account.
                var dir = CoreUpdate.NewPrivateDir();
                var tmp = Path.Combine(dir, "key.tmp");
                try
                {
                    using (Paths.HoldWriteDirectory(dir))
                    {
                        using (var output = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        { output.Write(keyFile, 0, keyFile.Length); output.Flush(true); }
                        using (SafeStorage.OpenReadNoFollow(tmp)) k.AddUserKey(new KcpKeyFile(tmp));
                    }
                }
                finally
                {
                    string error;
                    bool cleared = Secure.WipeFile(tmp, out error);
                    try { Directory.Delete(dir, false); } catch { }
                    if (!cleared) throw new IOException("Не удалось удалить временную копию ключ-файла: " + error);
                }
            }
            return k;
        }

        // Составной ключ требует и пароль, и ключ-файл — как раньше в WUV3.
        static byte[] ReadKeyFile(string path)
        {
            if (string.IsNullOrEmpty(path)) throw new FileNotFoundException("Ключ-файл не выбран.");
            if (!File.Exists(path)) throw new FileNotFoundException("Ключ-файл не найден: " + path);
            using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (input.Length == 0) throw new InvalidDataException("Ключ-файл пуст.");
                if (input.Length > 4 * 1024 * 1024) throw new InvalidDataException("Ключ-файл слишком большой (максимум 4 МБ).");
                var b = new byte[(int)input.Length];
                try
                {
                    int offset = 0, count;
                    while (offset < b.Length && (count = input.Read(b, offset, b.Length - offset)) > 0) offset += count;
                    if (offset != b.Length) throw new EndOfStreamException("Ключ-файл изменился во время чтения.");
                    return b;
                }
                catch { Array.Clear(b, 0, b.Length); throw; }
            }
        }

        public static KdbxStore Create(string p2, string keyFilePath)
        {
            Directory.CreateDirectory(Paths.Data);
            var kfBytes = string.IsNullOrEmpty(keyFilePath) ? null : ReadKeyFile(keyFilePath);
            try
            {
            var s = new KdbxStore
            {
                db = new PwDatabase(),
                p2 = p2,
                kf = kfBytes,
                kfRequired = kfBytes != null,
                p2Salt = Vault.Random(16),
                rcWrap = new byte[128],
                p2Fails = 0
            };
            s.db.New(IOConnectionInfo.FromPath(KdbxPath), MakeKey(p2, kfBytes));
            s.db.MemoryProtection.ProtectPassword = true;
            s.db.KdfParameters = ArgonParams();
            s.SyncToDb();
            s.Save();
            return s;
            }
            finally { if (kfBytes != null) Array.Clear(kfBytes, 0, kfBytes.Length); }
        }

        static KdfParameters ArgonParams()
        {
            var kp = new Argon2Kdf().GetDefaultParameters();
            kp.SetUInt64(Argon2Kdf.ParamMemory, 64UL << 20);
            kp.SetUInt64(Argon2Kdf.ParamIterations, 8UL);
            kp.SetUInt32(Argon2Kdf.ParamParallelism, 2U);
            return kp;
        }

        public sealed class KdfTuning
        {
            internal KdfParameters Parameters;
            public int MemoryMiB;
            public ulong Iterations;
            public long Milliseconds;
        }

        public int KdfMemoryMiB { get { return (int)(db.KdfParameters.GetUInt64(Argon2Kdf.ParamMemory, 64UL << 20) >> 20); } }
        public ulong KdfIterations { get { return db.KdfParameters.GetUInt64(Argon2Kdf.ParamIterations, 8UL); } }

        // Never silently reduce the existing work factor. Benchmark only on request.
        public KdfTuning CalibrateKdf(int memoryMiB, int targetMilliseconds)
        {
            if (memoryMiB < 64 || memoryMiB > 512 || targetMilliseconds < 500 || targetMilliseconds > 5000)
                throw new ArgumentOutOfRangeException();
            if (memoryMiB < KdfMemoryMiB) throw new InvalidOperationException("Нельзя уменьшать текущую память защиты базы.");
            var kdf = new Argon2Kdf();
            var kp = ArgonParams();
            kp.SetUInt64(Argon2Kdf.ParamMemory, (ulong)memoryMiB << 20);
            ulong floor = Math.Max(8UL, KdfIterations);
            ulong ceiling = Math.Min(KdbxSafety.MaxArgonIterations, KdbxSafety.MaxArgonWork / ((ulong)memoryMiB << 20));
            if (floor > ceiling) throw new InvalidOperationException("Параметры базы превышают бюджет WinUp. Защита не уменьшена.");
            kp.SetUInt64(Argon2Kdf.ParamIterations, floor);
            kdf.Randomize(kp);
            KdbxSafety.ValidateKdfParameters(kp);
            var input = Vault.Random(32);
            byte[] output = null;
            try
            {
                var watch = System.Diagnostics.Stopwatch.StartNew();
                output = kdf.Transform(input, kp);
                watch.Stop();
                Array.Clear(output, 0, output.Length); output = null;
                ulong iterations = Math.Max(floor, (ulong)Math.Min((double)ceiling, Math.Ceiling((double)floor * targetMilliseconds / Math.Max(1L, watch.ElapsedMilliseconds))));
                kp.SetUInt64(Argon2Kdf.ParamIterations, iterations);
                watch.Restart();
                output = kdf.Transform(input, kp);
                watch.Stop();
                return new KdfTuning { Parameters = kp, MemoryMiB = memoryMiB, Iterations = iterations, Milliseconds = watch.ElapsedMilliseconds };
            }
            finally { Array.Clear(input, 0, input.Length); if (output != null) Array.Clear(output, 0, output.Length); }
        }

        public void ApplyKdf(KdfTuning tuning)
        {
            if (tuning == null || tuning.Parameters == null || tuning.MemoryMiB < KdfMemoryMiB || tuning.Iterations < KdfIterations)
                throw new InvalidOperationException("Настройка уменьшает защиту базы.");
            KdbxSafety.ValidateKdfParameters(tuning.Parameters);
            db.KdfParameters = tuning.Parameters;
        }

        public static KdbxStore Open(string p2, string keyFilePath, out int left, out StoreResult res)
        {
            left = 0;
            res = StoreResult.Wrong;
            var s = ReadTab();
            var kfBytes = s.kfRequired || (s.kfUnknown && !string.IsNullOrEmpty(keyFilePath)) ? ReadKeyFile(keyFilePath) : null;
            try
            {
            var d = new PwDatabase();
            try { KdbxSafety.OpenDatabase(d, KdbxPath, MakeKey(p2, kfBytes), NullLog); }
            catch (InvalidCompositeKeyException)
            {
                s.p2Fails++;
                if (s.p2Fails >= P2Max) { WipeFiles(); res = StoreResult.Wiped; return null; }
                s.WriteTab();
                left = P2Max - s.p2Fails;
                return null;
            }
            // Повреждённая база (KeePassLib: FormatException «file signature is invalid») — по-русски и с путём спасения.
            catch (FormatException) { throw new InvalidDataException("Файл базы повреждён или не является базой WinUp.\nВосстановите data\\vault.kdbx из папки резерва (vault-*.kdbx)."); }
            s.db = d; s.p2 = p2; s.kf = kfBytes;
            s.p2Fails = 0;
            // Сайдкар был создан без входа (его не было или он записан после неверной попытки) —
            // теперь состав ключа известен.
            s.tabRecreated = s.kfUnknown;
            if (s.kfUnknown) { s.kfRequired = kfBytes != null; s.kfUnknown = false; }
            s.LoadRecoveryCode();
            s.LoadFromDb();
            s.WriteTab();
            left = P2Max;
            res = StoreResult.Ok;
            return s;
            }
            finally { if (kfBytes != null) Array.Clear(kfBytes, 0, kfBytes.Length); }
        }

        // Открытие копии кодом восстановления. Ошибки засчитываются в попытки пароля 2.
        public static KdbxStore OpenByRecovery(string code, out int left, out StoreResult res)
        {
            left = 0;
            res = StoreResult.Wrong;
            var s = ReadTab();
            if (!File.Exists(RecoveryPath)) throw new InvalidOperationException("Файл восстановления не найден.");
            var norm = Vault.NormalizeCode(code);
            var d = new PwDatabase();
            try
            {
            try { KdbxSafety.OpenDatabase(d, RecoveryPath, MakeKey(norm, null), NullLog); }
            catch (InvalidCompositeKeyException)
            {
                s.p2Fails++;
                if (s.p2Fails >= P2Max) { WipeFiles(); res = StoreResult.Wiped; return null; }
                s.WriteTab();
                left = P2Max - s.p2Fails;
                return null;
            }
            // Повреждённая копия восстановления — по-русски и с путём спасения.
            catch (FormatException) { throw new InvalidDataException("Файл восстановления повреждён или не является базой WinUp.\nВосстановите data\\recovery.kdbx из папки резерва (recovery-*.kdbx)."); }
            // Вход кодом: старый пароль базы недействителен (смена обязательна).
            // База открыта из копии recovery.kdbx; Save() всегда пишет в основной vault.kdbx.
            // Сайдкар на диске не трогаем: если пользователь отменит обязательную смену пароля, старый
            // пароль обязан остаться рабочим. Счётчик сбрасываем только в памяти — на диск его запишет
            // SetDbPassword+Save; сам код держим развёрнутым (s.rc), чтобы Save перепаковал recovery.kdbx
            // и обёртку в сайдкаре после смены пароля.
            s.db = d; s.p2 = null; s.kf = null; s.rc = norm; s.hasRc = true;
            s.p2Fails = 0;
            s.LoadFromDb();
            left = P2Max;
            res = StoreResult.Ok;
            return s;
            }
            finally { Secure.Wipe(norm); }
        }

        // Обёртка переменной длины: IV(16) | AES-CBC(payload) | HMAC-SHA256(32).
        // Ключи AES и HMAC — половины кея (как в Wrap хранилища, но без фиксированной длины).
        internal static byte[] WrapVar(byte[] kek, byte[] plain)
        {
            byte[] iv, ct;
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Slice(kek, 0, 32);
                iv = Vault.Random(16);
                aes.IV = iv;
                using (var e = aes.CreateEncryptor()) ct = e.TransformFinalBlock(plain, 0, plain.Length);
            }
            var w = new byte[16 + ct.Length + 32];
            Buffer.BlockCopy(iv, 0, w, 0, 16);
            Buffer.BlockCopy(ct, 0, w, 16, ct.Length);
            using (var h = new System.Security.Cryptography.HMACSHA256(Slice(kek, 32, 32)))
                Buffer.BlockCopy(h.ComputeHash(w, 0, w.Length - 32), 0, w, w.Length - 32, 32);
            return w;
        }

        internal static byte[] UnwrapVar(byte[] kek, byte[] w)
        {
            if (w == null || w.Length < 64) return null;
            var macLen = w.Length - 32;
            byte[] mac;
            using (var h = new System.Security.Cryptography.HMACSHA256(Slice(kek, 32, 32))) mac = h.ComputeHash(w, 0, macLen);
            if (!FixedEquals(mac, Slice(w, macLen, 32))) return null;
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Slice(kek, 0, 32);
                aes.IV = Slice(w, 0, 16);
                aes.Padding = System.Security.Cryptography.PaddingMode.None;
                var plain = new byte[macLen - 16];
                var pin = GCHandle.Alloc(plain, GCHandleType.Pinned);
                try
                {
                using (var d = aes.CreateDecryptor())
                {
                    try
                    {
                        // Keep padded plaintext in an owned buffer instead of the
                        // implementation's untracked PKCS#7 temporary copy.
                        int count = d.TransformBlock(w, 16, plain.Length, plain, 0);
                        if (count != plain.Length || count == 0) return null;
                        var tail = d.TransformFinalBlock(new byte[0], 0, 0);
                        if (tail.Length != 0) { Array.Clear(tail, 0, tail.Length); return null; }
                        int padding = plain[count - 1];
                        if (padding < 1 || padding > 16 || padding > count) return null;
                        int mismatch = 0;
                        for (int i=0; i<padding; i++) mismatch |= plain[count-1-i] ^ padding;
                        if (mismatch != 0) return null;
                        var result = new byte[count-padding];
                        Buffer.BlockCopy(plain, 0, result, 0, result.Length);
                        return result;
                    }
                    catch { return null; }
                }
                }
                finally { Array.Clear(plain, 0, plain.Length); pin.Free(); }
            }
        }

        string UnwrapRc()
        {
            if (!hasRc || rcWrap == null || rcWrap.Length == 0) return null;
            var kek = UseMaster((pw, bytes) => Vault.Kek(pw, bytes, p2Salt, RcIters, 1));
            byte[] raw;
            try { raw = UnwrapVar(kek, rcWrap); }
            finally { Array.Clear(kek, 0, kek.Length); }
            if (raw == null) return null;
            // Байты кода — сырая копия секрета, затираем сразу после превращения в строку.
            var pin = GCHandle.Alloc(raw, GCHandleType.Pinned);
            try { return Encoding.UTF8.GetString(raw); }
            finally { Array.Clear(raw, 0, raw.Length); pin.Free(); }
        }

        // ---------------- сохранение ----------------

        public void Save()
        {
            if (saveFailed) throw new InvalidOperationException("Предыдущее сохранение не завершено. Откройте базу заново.");
            SyncToDb();
            // Явный путь: база могла быть открыта из recovery.kdbx (вход кодом) — сохраняем в vault.kdbx.
            var writes = new List<KeyValuePair<string, Action<Stream>>>();
            writes.Add(new KeyValuePair<string, Action<Stream>>(KdbxPath, stream => new KdbxFile(db).Save(new Paths.LeaveOpenStream(stream), null, KdbxFormat.Default, NullLog)));
            // Свежая копия кодом восстановления: код развёрнут, пока база открыта полным входом.
            if (recoveryCode.HasValue && masterPassword.HasValue)
            {
                var recoveryKey = recoveryCode.Use(code => MakeKey(code, null));
                // finally: при сбое SaveAs мастер-ключом не должен остаться код восстановления —
                // иначе следующий успешный Save зашифрует vault.kdbx кодом, и пароль базы «перестанет работать».
                writes.Add(new KeyValuePair<string, Action<Stream>>(RecoveryPath, stream => {
                    var saveKey = db.MasterKey; db.MasterKey = recoveryKey;
                    try { new KdbxFile(db).Save(new Paths.LeaveOpenStream(stream), null, KdbxFormat.Default, NullLog); }
                    finally { db.MasterKey = saveKey; }
                }));
            }
            var tab = TabBytes();
            writes.Add(new KeyValuePair<string, Action<Stream>>(TabPath, stream => stream.Write(tab, 0, tab.Length)));
            try { Paths.AtomicWriteBatch(writes); db.Modified = false; }
            catch { saveFailed = true; throw; }
            finally { Array.Clear(tab, 0, tab.Length); }
        }
        bool saveFailed;
        internal bool SaveFailed { get { return saveFailed; } }

        void SaveDatabase(string path)
        {
            // KeePassLib's PwDatabase defaults to direct truncating writes. Keep
            // its serializer, but commit the complete encrypted stream atomically.
            Paths.AtomicWriteStream(path, stream => new KdbxFile(db).Save(new Paths.LeaveOpenStream(stream), null, KdbxFormat.Default, NullLog));
            db.Modified = false;
        }

        // Смена пароля 2 (и ключ-файла). Код восстановления продолжает действовать — обёртка переписывается.
        public void SetDbPassword(string p2new, string keyFilePath)
        {
            var newKeyFile = string.IsNullOrEmpty(keyFilePath) ? null : ReadKeyFile(keyFilePath);
            try
            {
                var newKey = MakeKey(p2new, newKeyFile);
                p2 = p2new;
                kf = newKeyFile;
                kfRequired = newKeyFile != null;
                db.MasterKey = newKey;
            }
            finally { if (newKeyFile != null) Array.Clear(newKeyFile, 0, newKeyFile.Length); }
            // Соль обёртки кода не должна переживать смену пароля (как в старом хранилище).
            p2Salt = Vault.Random(16);
            if (recoveryCode.HasValue) RewrapRc();
            p2Fails = 0;
        }

        // Новый код восстановления; прежний перестаёт работать. recovery.kdbx обновится при Save.
        public string MakeRecoveryCode()
        {
            var raw = new char[24];
            var bytes = Vault.Random(24);
            for (int i = 0; i < 24; i++) raw[i] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[bytes[i] & 31];
            var code = new string(raw);
            rc = code;
            RecoveryNeedsRepair = false;
            Array.Clear(raw, 0, raw.Length);
            Array.Clear(bytes, 0, bytes.Length);
            var parts = new List<string>();
            try
            {
                hasRc = true;
                RewrapRc();
                for (int i = 0; i < 24; i += 4) parts.Add(code.Substring(i, 4));
                return string.Join("-", parts);
            }
            finally { Secure.Wipe(code); foreach (var part in parts) Secure.Wipe(part); }
        }

        void RewrapRc()
        {
            p2Salt = p2Salt ?? Vault.Random(16);
            var kek = UseMaster((pw, bytes) => Vault.Kek(pw, bytes, p2Salt, RcIters, 1));
            // Байты кода — сырая копия секрета, затираем сразу после обёртки.
            var raw = recoveryCode.Use(code => Encoding.UTF8.GetBytes(code));
            var pin = GCHandle.Alloc(raw, GCHandleType.Pinned);
            try { rcWrap = WrapVar(kek, raw); }
            finally { Array.Clear(kek, 0, kek.Length); Array.Clear(raw, 0, raw.Length); pin.Free(); }
        }

        // ---------------- PIN: обёртка составного ключа в памяти процесса ----------------

        public sealed class PinSession
        {
            internal byte[] Salt;
            readonly SecretBytes wrappedKey = new SecretBytes();
            internal byte[] Wrap { set { wrappedKey.Set(value); } }
            internal byte[] ReadWrap() { return wrappedKey.Read(); }
            internal int Fails;
            internal void Clear()
            {
                wrappedKey.Dispose();
                if (Salt != null) Array.Clear(Salt, 0, Salt.Length);
                Salt = null;
            }
        }

        public PinSession MakePin(string pinCode)
        {
            var salt = Vault.Random(16);
            var kek = Vault.Kek(pinCode, null, salt, PinIters, 1);
            // Копия составного ключа в чистом виде — затираем сразу после обёртки.
            var key = SerializeKey();
            byte[] w = null;
            try { w = WrapVar(kek, key); return new PinSession { Salt = salt, Wrap = w }; }
            finally
            {
                Array.Clear(kek, 0, kek.Length); Array.Clear(key, 0, key.Length);
                if (w != null) Array.Clear(w, 0, w.Length);
            }
        }

        // Открытие по PIN: разворачивает составной ключ и открывает базу (Argon2), попытки файла не расходуются.
        public static StoreResult OpenWithPin(string pinCode, PinSession pin, out KdbxStore store)
        {
            store = null;
            if (pin == null || pin.Salt == null) return StoreResult.Wrong;
            var kek = Vault.Kek(pinCode, null, pin.Salt, PinIters, 1);
            var wrap = pin.ReadWrap();
            byte[] raw;
            try { raw = UnwrapVar(kek, wrap); }
            finally { Array.Clear(kek, 0, kek.Length); if (wrap != null) Array.Clear(wrap, 0, wrap.Length); }
            if (raw == null) return StoreResult.Wrong;
            try { return OpenWithKey(raw, out store); }
            finally { Array.Clear(raw, 0, raw.Length); }
        }

        // Открытие по развёрнутому составному ключу (PIN, Windows Hello). Попытки файла не расходуются:
        // неверный ключ здесь — это устаревшая обёртка (пароль базы сменили), а не подбор.
        public static StoreResult OpenWithKey(byte[] raw, out KdbxStore store)
        {
            store = null;
            if (raw == null || raw.Length < 8) return StoreResult.Wrong;
            int pwLength = BitConverter.ToInt32(raw, 0);
            if (pwLength < 0 || pwLength > raw.Length - 8) return StoreResult.Wrong;
            int kfLen = BitConverter.ToInt32(raw, 4 + pwLength);
            if (kfLen < 0 || kfLen > 4 * 1024 * 1024 || kfLen != raw.Length - pwLength - 8) return StoreResult.Wrong;
            var p2b = new byte[pwLength];
            Buffer.BlockCopy(raw, 4, p2b, 0, p2b.Length);
            var kfb = kfLen > 0 ? Slice(raw, 4 + p2b.Length + 4, kfLen) : null;
            var p2s = Encoding.UTF8.GetString(p2b);
            var textPin = GCHandle.Alloc(p2s, GCHandleType.Pinned);
            // Байты пароля затираем сразу; строку p2s — после открытия базы.
            Array.Clear(p2b, 0, p2b.Length);
            var d = new PwDatabase();
            try
            {
            var s = ReadTab();
            try { KdbxSafety.OpenDatabase(d, KdbxPath, MakeKey(p2s, kfb), NullLog); }
            catch (InvalidCompositeKeyException) { Secure.Wipe(p2s); return StoreResult.Wrong; }
            s.db = d; s.p2 = p2s; s.kf = kfb;
            Secure.Wipe(p2s);
            s.LoadRecoveryCode();
            s.LoadFromDb();
            store = s;
            return StoreResult.Ok;
            }
            finally { Secure.Wipe(p2s); textPin.Free(); if (kfb != null) Array.Clear(kfb, 0, kfb.Length); }
        }

        // Копия составного ключа для обёртки (Windows Hello). Вызывающий затирает массив сразу после использования.
        public byte[] KeyMaterial() { return SerializeKey(); }

        byte[] SerializeKey()
        {
            return UseMaster((pw, bytes) =>
            {
                var p2b = Encoding.UTF8.GetBytes(pw ?? "");
                var pin = GCHandle.Alloc(p2b, GCHandleType.Pinned);
                var kfb = bytes ?? new byte[0];
                try
                {
                    var b = new byte[4 + p2b.Length + 4 + kfb.Length];
                    Buffer.BlockCopy(BitConverter.GetBytes(p2b.Length), 0, b, 0, 4);
                    Buffer.BlockCopy(p2b, 0, b, 4, p2b.Length);
                    Buffer.BlockCopy(BitConverter.GetBytes(kfb.Length), 0, b, 4 + p2b.Length, 4);
                    Buffer.BlockCopy(kfb, 0, b, 8 + p2b.Length, kfb.Length);
                    return b;
                }
                finally { Array.Clear(p2b, 0, p2b.Length); pin.Free(); }
            });
        }

        // ---------------- отображение WinUp <-> KDBX ----------------

        void LoadFromDb()
        {
            Entries.Clear();
            Otp.Clear();
            var otpGroup = FindOtpGroup(false);
            foreach (var pe in db.RootGroup.Entries)
                Entries.Add(FromEntry(pe));
            if (otpGroup != null)
                foreach (var pe in otpGroup.Entries)
                {
                    var o = OtpFromEntry(pe);
                    if (o != null) Otp.Add(o);
                }
        }

        void SyncToDb()
        {
            var otpGroup = FindOtpGroup(true);

            // 1) аккаунты 2FA: новые UUID + карта «старый Id → новый UUID» для ссылок записей
            var existingOtp = otpGroup.Entries.ToDictionary(e => e.Uuid.ToHexString());
            var keepOtp = new HashSet<string>();
            var otpIdMap = new Dictionary<string, string>();
            foreach (var o in Otp)
            {
                string id = o.Id ?? "";
                PwEntry pe;
                if (id.Length == 32 && existingOtp.TryGetValue(id, out pe)) { }
                else
                {
                    pe = new PwEntry(true, true);
                    if (id.Length > 0) otpIdMap[id] = pe.Uuid.ToHexString();
                    o.Id = pe.Uuid.ToHexString();
                    otpGroup.AddEntry(pe, true);
                }
                UpdateWithHistory(pe, p=>FillOtp(p,o), existingOtp.ContainsKey(pe.Uuid.ToHexString()));
                keepOtp.Add(pe.Uuid.ToHexString());
            }
            foreach (var kv in existingOtp)
                if (!keepOtp.Contains(kv.Key)) MoveToTrash(kv.Value,true);
            if (otpIdMap.Count > 0)
                foreach (var le in Entries)
                {
                    string nid;
                    if (!string.IsNullOrEmpty(le.OtpId) && otpIdMap.TryGetValue(le.OtpId, out nid)) le.OtpId = nid;
                }

            // 2) записи: WinUp.OtpRef уже обновлён картой
            var existing = db.RootGroup.Entries.Where(e => !InGroup(otpGroup, e)).ToDictionary(e => e.Uuid.ToHexString());
            var keep = new HashSet<string>();
            foreach (var le in Entries)
            {
                string id = le.Id ?? "";
                PwEntry pe;
                if (id.Length == 32 && existing.TryGetValue(id, out pe)) { }
                else { pe = new PwEntry(true, true); le.Id = pe.Uuid.ToHexString(); db.RootGroup.AddEntry(pe, true); }
                UpdateWithHistory(pe, p=>FillEntry(p,le), existing.ContainsKey(pe.Uuid.ToHexString()));
                keep.Add(pe.Uuid.ToHexString());
            }
            foreach (var kv in existing)
                if (!keep.Contains(kv.Key)) MoveToTrash(kv.Value,false);
        }

        PwGroup FindOtpGroup(bool create)
        {
            var g = db.RootGroup.Groups.FirstOrDefault(x => x.Name == OtpGroupName);
            if (g == null && create)
            {
                g = new PwGroup(true, true, OtpGroupName, PwIcon.Key);
                db.RootGroup.AddGroup(g, true);
            }
            return g;
        }

        static bool InGroup(PwGroup g, PwEntry e) { return g != null && g.Entries.IndexOf(e) >= 0; }

        static void FillEntry(PwEntry pe, LoginEntry le)
        {
            foreach(var name in pe.Strings.GetKeys().Where(IsUserField).ToList())pe.Strings.Remove(name);
            foreach(var field in le.CustomFields){ValidateFieldName(field.Name);field.UseValue(v=>{pe.Strings.Set(field.Name,ProtectedUtf8(v));return 0;});}
            pe.Strings.Set(PwDefs.TitleField, new ProtectedString(false, le.Name ?? ""));
            pe.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, le.Login ?? ""));
            le.UsePassword(pw => { pe.Strings.Set(le.Kind == "passkey" ? "KPEX_PASSKEY_PRIVATE_KEY_PEM" : PwDefs.PasswordField, ProtectedUtf8(pw)); return 0; });
            if (le.Kind == "passkey") {
                pe.Strings.Remove(PwDefs.PasswordField);
                SetStr(pe,"KPEX_PASSKEY_CREDENTIAL_ID",le.Args);
                SetStr(pe,"KPEX_PASSKEY_RELYING_PARTY",le.Target);
                SetStr(pe,"KPEX_PASSKEY_USERNAME",le.Login);
                SetStr(pe,"KPEX_PASSKEY_USER_HANDLE",le.Window);
                SetStr(pe,"KPEX_PASSKEY_FLAG_BE",le.PasskeyBackupEligible ? "1" : "0");
                SetStr(pe,"KPEX_PASSKEY_FLAG_BS",le.PasskeyBackupEligible && le.PasskeyBackedUp ? "1" : "0");
            }
            pe.Strings.Set(PwDefs.UrlField, new ProtectedString(false, le.Target ?? ""));
            pe.Strings.Set(PwDefs.NotesField, new ProtectedString(false, le.Notes ?? ""));
            SetStr(pe, "WinUp.Kind", le.Kind);
            SetStr(pe, "WinUp.Login2", le.Login2);
            SetStr(pe, "WinUp.Category", le.Category);
            SetStr(pe, "WinUp.Pinned", le.Pinned ? "1" : "0");
            SetStr(pe, "WinUp.AppTarget", le.AppTarget);
            SetStr(pe, "WinUp.LoginUrl", le.LoginUrl);
            SetStr(pe, "WinUp.LoginProfile", le.LoginProfile);
            SetStr(pe, "WinUp.PasskeyRef", le.PasskeyId);
            le.UseRecoveryCodes(codes => { pe.Strings.Set("WinUp.RecoveryCodes", ProtectedUtf8(codes)); return 0; });
            SetStr(pe, "WinUp.Args", le.Args);
            SetStr(pe, "WinUp.Browser", le.Browser);
            SetStr(pe, "WinUp.Window", le.Window);
            var delay = DelayOf(le.Delay); // FromEntry читает только 0..60 — пишем в том же диапазоне
            SetStr(pe, "WinUp.Delay", delay > 0 ? delay.ToString() : "");
            SetStr(pe, "WinUp.AutoEnter", le.AutoEnter ? "1" : "");
            SetStr(pe, "WinUp.TwoFa", le.TwoFa);
            SetStr(pe, "WinUp.OtpRef", le.OtpId);
            pe.IconId = le.Kind == "app" ? PwIcon.World : PwIcon.Key;
        }

        static void SetStr(PwEntry pe, string name, string value)
        {
            if (string.IsNullOrEmpty(value)) pe.Strings.Remove(name);
            else pe.Strings.Set(name, new ProtectedString(false, value));
        }

        static string GetStr(PwEntry pe, string name)
        {
            var ps = pe.Strings.Get(name);
            return ps == null ? null : ps.ReadString();
        }

        static ProtectedString ProtectedUtf8(string text)
        {
            // The string constructor and ReadString retain plaintext in KeePass.
            // Only the byte constructor + ReadUtf8 preserve protected storage.
            var bytes = Encoding.UTF8.GetBytes(text ?? "");
            try { return new ProtectedString(true, bytes); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }

        static string ReadSecret(PwEntry entry, string field)
        {
            var source = entry.Strings.Get(field);
            if (source == null) return null;
            var bytes = source.ReadUtf8();
            var pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                entry.Strings.Set(field, new ProtectedString(true, bytes));
                return Encoding.UTF8.GetString(bytes);
            }
            finally { Array.Clear(bytes, 0, bytes.Length); pin.Free(); }
        }

        static LoginEntry FromEntry(PwEntry pe)
        {
            var entry = new LoginEntry
            {
                Id = pe.Uuid.ToHexString(),
                Name = pe.Strings.ReadSafe(PwDefs.TitleField),
                Login = pe.Strings.ReadSafe(PwDefs.UserNameField),
                Login2 = GetStr(pe, "WinUp.Login2"),
                Category = GetStr(pe, "WinUp.Category"),
                Pinned = GetStr(pe, "WinUp.Pinned") == "1",
                AppTarget = GetStr(pe, "WinUp.AppTarget"),
                LoginUrl = GetStr(pe, "WinUp.LoginUrl"),
                LoginProfile = GetStr(pe, "WinUp.LoginProfile"),
                PasskeyId = GetStr(pe, "WinUp.PasskeyRef"),
                Target = pe.Strings.ReadSafe(PwDefs.UrlField),
                Notes = pe.Strings.ReadSafe(PwDefs.NotesField),
                Kind = GetStr(pe, "WinUp.Kind") ?? "site",
                Args = GetStr(pe, "WinUp.Args"),
                Browser = GetStr(pe, "WinUp.Browser"),
                Window = GetStr(pe, "WinUp.Window"),
                Delay = ParseInt(GetStr(pe, "WinUp.Delay"), 3),
                AutoEnter = GetStr(pe, "WinUp.AutoEnter") == "1",
                TwoFa = GetStr(pe, "WinUp.TwoFa") ?? "none",
                OtpId = GetStr(pe, "WinUp.OtpRef")
            };
            if (pe.Strings.Get("KPEX_PASSKEY_PRIVATE_KEY_PEM") != null) {
                entry.Kind="passkey"; entry.Args=GetStr(pe,"KPEX_PASSKEY_CREDENTIAL_ID");
                entry.Target=GetStr(pe,"KPEX_PASSKEY_RELYING_PARTY"); entry.Login=GetStr(pe,"KPEX_PASSKEY_USERNAME");
                entry.Window=GetStr(pe,"KPEX_PASSKEY_USER_HANDLE");
                entry.PasskeyBackupEligible=GetStr(pe,"KPEX_PASSKEY_FLAG_BE")=="1";
                entry.PasskeyBackedUp=entry.PasskeyBackupEligible && GetStr(pe,"KPEX_PASSKEY_FLAG_BS")=="1";
            }
            string passwordField = entry.Kind == "passkey" ? "KPEX_PASSKEY_PRIVATE_KEY_PEM" : PwDefs.PasswordField;
            var protectedPassword = pe.Strings.Get(passwordField);
            if (protectedPassword != null)
            {
                var password = ReadSecret(pe, passwordField);
                try { entry.Password = password; }
                finally { Secure.Wipe(password); }
            }
            var codes = ReadSecret(pe, "WinUp.RecoveryCodes");
            try { entry.RecoveryCodes = codes; }
            finally { Secure.Wipe(codes); }
            foreach(var name in pe.Strings.GetKeys().Where(IsUserField)){
                var value=ReadSecret(pe,name);try{entry.CustomFields.Add(new AccountSecretField{Name=name,Value=value});}finally{Secure.Wipe(value);}
            }
            return entry;
        }

        static int ParseInt(string s, int def)
        {
            int v;
            // Отсутствующее поле — 0 (не «3 по умолчанию»: у записи могло быть выключено ожидание).
            return int.TryParse(s, out v) && v >= 0 && v <= 60 ? v : (s == null ? 0 : def);
        }

        static void FillOtp(PwEntry pe, OtpEntry o)
        {
            pe.Strings.Set(PwDefs.TitleField, new ProtectedString(false, string.IsNullOrEmpty(o.Account) ? (o.Issuer ?? "") : (o.Issuer ?? "") + " (" + o.Account + ")"));
            pe.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, o.Account ?? ""));
            pe.Strings.Set(PwDefs.NotesField, new ProtectedString(false, o.Notes ?? ""));
            var uri = o.Uri();
            try { pe.Strings.Set("otp", ProtectedUtf8(uri)); }
            finally { Secure.Wipe(uri); }
            pe.IconId = PwIcon.Clock;
        }

        static OtpEntry OtpFromEntry(PwEntry pe)
        {
            var uriPs = pe.Strings.Get("otp");
            if (uriPs == null) return null;
            var uri = ReadSecret(pe, "otp");
            try
            {
            if (string.IsNullOrEmpty(uri)) return null;
            var o = OtpImport.FromUri(uri, new List<string>());
            if (o == null) return null;
            o.Id = pe.Uuid.ToHexString();
            o.Notes = pe.Strings.ReadSafe(PwDefs.NotesField);
            o.Account = AccountFromOtpUri(uri, o.Issuer);
            return o;
            }
            finally { Secure.Wipe(uri); }
        }

        // Аккаунт — часть метки после «:». OtpEntry.Uri() без аккаунта пишет метку из одного сервиса,
        // а FromUri в этом случае подставляет в аккаунт название сервиса — при каждом сохранении
        // пустой аккаунт превращался в «Steam (Steam)». Базы, уже записанные с такой подменой
        // (метка «Steam:Steam»), чиним: аккаунт, совпадающий с сервисом, считаем пустым.
        static string AccountFromOtpUri(string uri, string issuer)
        {
            int pathAt = uri.IndexOf('/', "otpauth://".Length), queryAt = uri.IndexOf('?');
            if (pathAt < 0 || queryAt <= pathAt) return "";
            var label = Uri.UnescapeDataString(uri.Substring(pathAt + 1, queryAt - pathAt - 1));
            int colon = label.IndexOf(':');
            var account = colon >= 0 ? label.Substring(colon + 1).Trim() : "";
            return string.Equals(account, issuer ?? "", StringComparison.Ordinal) ? "" : account;
        }

        // ---------------- миграция из старого хранилища ----------------

        // Перенос открытой старой базы (WUV1/2/3) в vault.kdbx: создать с тем же ключом,
        // записать, переоткрыть и сверить каждое поле каждой записи и каждый аккаунт 2FA.
        // При полном совпадении старый файл переименовывается в vault-legacy.dat (не удаляется).
        // При любом расхождении — исключение, новый файл удаляется, старый не тронут.
        public static KdbxStore MigrateFromLegacy(Vault legacy, string p2, string keyFilePath, out string report)
        {
            Directory.CreateDirectory(Paths.Data);
            var kfBytes = string.IsNullOrEmpty(keyFilePath) ? null : ReadKeyFile(keyFilePath);
            try
            {
            var s = new KdbxStore
            {
                db = new PwDatabase(),
                p2 = p2,
                kf = kfBytes,
                kfRequired = kfBytes != null,
                p2Salt = Vault.Random(16),
                rcWrap = new byte[128],
                p2Fails = 0
            };
            s.db.New(IOConnectionInfo.FromPath(KdbxPath), MakeKey(p2, kfBytes));
            s.db.MemoryProtection.ProtectPassword = true;
            s.db.KdfParameters = ArgonParams();
            // Копии строк, а не ссылки: после переноса вызывающий затирает старую базу (legacy.Lock →
            // Secure.Wipe пишет нули прямо в строки), и общие экземпляры обнулили бы логины, пароли
            // и секреты 2FA уже перенесённой базы.
            s.Entries = legacy.Data.Entries.Select(Copy).ToList();
            s.Otp = legacy.Data.Otp.Select(Copy).ToList();
            s.SyncToDb();
            s.SaveDatabase(KdbxPath);

            // контрольная сверка: переоткрыть и сравнить всё. Сопоставление — по позиции:
            // s.Entries[i] — копия legacy.Data.Entries[i], после SyncToDb у неё UUID записи в kdbx
            // (по названию сопоставлять нельзя: две записи «Gmail» — обычное дело).
            var check = new PwDatabase();
            KdbxSafety.OpenDatabase(check, KdbxPath, MakeKey(p2, kfBytes), NullLog);
            var diff = Compare(check, legacy, s);
            check.Close();
            if (diff != null) { try { File.Delete(KdbxPath); } catch { } throw new InvalidDataException("Перенос не прошёл сверку: " + diff); }

            // старый файл — в архив (не удаляем: пусть пользователь сам решит, когда убрать)
            try { if (File.Exists(LegacyPath)) File.Move(LegacyPath, LegacyArchivePath); } catch { }
            s.WriteTab();

            report = "записей: " + s.Entries.Count + ", аккаунтов 2FA: " + s.Otp.Count;
            return s;
            }
            finally { if (kfBytes != null) Array.Clear(kfBytes, 0, kfBytes.Length); }
        }

        // Сверка перенесённой базы с исходной. migrated.Entries[i] / migrated.Otp[i] — копии i-х элементов
        // старой базы, их Id после SyncToDb — UUID в kdbx: по нему и ищем (названия могут совпадать).
        // Пустое и отсутствующее поле считаются одинаковыми; значения, которые kdbx хранит
        // нормализованными (тип, режим 2FA, пауза 0..60, ключ base32), сравниваются нормализованными.
        static string Compare(PwDatabase created, Vault legacy, KdbxStore migrated)
        {
            var otpGroup = created.RootGroup.Groups.FirstOrDefault(g => g.Name == OtpGroupName);
            var entries = created.RootGroup.Entries.Where(e => otpGroup == null || otpGroup.Entries.IndexOf(e) < 0)
                .ToDictionary(e => e.Uuid.ToHexString());
            var otps = otpGroup == null ? new Dictionary<string, PwEntry>() : otpGroup.Entries.ToDictionary(e => e.Uuid.ToHexString());
            if (entries.Count != legacy.Data.Entries.Count) return "число записей";
            if (otps.Count != legacy.Data.Otp.Count) return "число аккаунтов 2FA";

            for (int i = 0; i < legacy.Data.Otp.Count; i++)
            {
                var lo = legacy.Data.Otp[i];
                PwEntry pe;
                if (!otps.TryGetValue(migrated.Otp[i].Id ?? "", out pe)) return "нет аккаунта 2FA «" + lo.Title + "»";
                var back = OtpFromEntry(pe);
                if (back == null || !back.UseSecret(a => lo.UseSecret(b => string.Equals(a, b, StringComparison.Ordinal))) ||
                    N(back.Issuer) != N(lo.Issuer) || N(back.Account) != (lo.Account == lo.Issuer ? "" : N(lo.Account)) || N(back.Notes) != N(lo.Notes) ||
                    back.Algorithm != (lo.Algorithm ?? "SHA1") || back.Digits != lo.Digits || back.Period != lo.Period)
                    return "поле аккаунта 2FA «" + lo.Title + "»";
            }

            for (int i = 0; i < legacy.Data.Entries.Count; i++)
            {
                var le = legacy.Data.Entries[i];
                PwEntry pe;
                if (!entries.TryGetValue(migrated.Entries[i].Id ?? "", out pe)) return "нет записи «" + le.Name + "»";
                var back = FromEntry(pe);
                if (N(back.Name) != N(le.Name) || N(back.Login) != N(le.Login) || !back.UsePassword(a => le.UsePassword(b => N(a) == N(b))) ||
                    N(back.Target) != N(le.Target) || N(back.Notes) != N(le.Notes) || N(back.Window) != N(le.Window) ||
                    N(back.Args) != N(le.Args) || N(back.Browser) != N(le.Browser) ||
                    N(back.Login2) != N(le.Login2) || N(back.AppTarget) != N(le.AppTarget) || N(back.PasskeyId) != N(le.PasskeyId) || N(back.LoginUrl)!=N(le.LoginUrl) || N(back.LoginProfile)!=N(le.LoginProfile) ||
                    !back.UseRecoveryCodes(a => le.UseRecoveryCodes(b => N(a) == N(b))) ||
                    (le.Kind=="passkey" && (back.PasskeyBackupEligible!=le.PasskeyBackupEligible || back.PasskeyBackedUp!=(le.PasskeyBackupEligible && le.PasskeyBackedUp))) ||
                    back.Kind != KindOf(le.Kind) || back.TwoFa != TwoFaOf(le.TwoFa) || back.Delay != DelayOf(le.Delay) ||
                    back.AutoEnter != le.AutoEnter || back.Pinned != le.Pinned || N(back.Category) != N(le.Category))
                    return "поле записи «" + le.Name + "»";
                // Ссылка на 2FA: старый Id резолвится в старой базе, новый UUID — в новой.
                if (!string.IsNullOrEmpty(le.OtpId))
                {
                    int j = legacy.Data.Otp.FindIndex(x => x.Id == le.OtpId);
                    var expected = j >= 0 ? migrated.Otp[j].Id : le.OtpId; // висячая ссылка переносится как есть
                    if (back.OtpId != expected) return "ссылка 2FA записи «" + le.Name + "»";
                }
            }
            return null;
        }

        static string N(string v) { return v ?? ""; }
        static string KindOf(string k) { return string.IsNullOrEmpty(k) ? "site" : k; }
        static string TwoFaOf(string t) { return string.IsNullOrEmpty(t) ? "none" : t; }
        static int DelayOf(int d) { return Math.Max(0, Math.Min(60, d)); }

        static LoginEntry Copy(LoginEntry e)
        {
            return e.UsePassword(pw => e.UseRecoveryCodes(codes => new LoginEntry
            {
                Id = Uninterned(e.Id), Name = Uninterned(e.Name), Kind = Uninterned(e.Kind), Target = Uninterned(e.Target),
                Args = Uninterned(e.Args), Browser = Uninterned(e.Browser), Window = Uninterned(e.Window),
                PasskeyBackupEligible=e.PasskeyBackupEligible, PasskeyBackedUp=e.PasskeyBackedUp,
                Login = Uninterned(e.Login), Login2 = Uninterned(e.Login2), AppTarget = Uninterned(e.AppTarget),
                LoginUrl = Uninterned(e.LoginUrl), LoginProfile = Uninterned(e.LoginProfile),
                Category = Uninterned(e.Category), Pinned=e.Pinned,
                PasskeyId = Uninterned(e.PasskeyId), RecoveryCodes = codes, Password = pw, AutoEnter = e.AutoEnter,
                TwoFa = Uninterned(e.TwoFa), OtpId = Uninterned(e.OtpId), Delay = e.Delay, Notes = Uninterned(e.Notes)
            }));
        }

        static OtpEntry Copy(OtpEntry o)
        {
            return o.UseSecret(secret => new OtpEntry
            {
                Id = Uninterned(o.Id), Issuer = Uninterned(o.Issuer), Account = Uninterned(o.Account), Secret = secret,
                Algorithm = Uninterned(o.Algorithm), Digits = o.Digits, Period = o.Period, Notes = Uninterned(o.Notes)
            });
        }

        // ---------------- блокировка ----------------

        public void Lock()
        {
            if (db != null)
            {
                // KeePass password/OTP fields use protected UTF-8 buffers; WinUp
                // owns separate Windows-protected buffers, all cleared below.
                try { db.Close(); } catch { }
                db = null;
            }
            masterPassword.Clear();
            recoveryCode.Clear();
            keyFile.Dispose();
            // Метаданные записей (логин, URL, аргументы, заголовки окон) тоже секреты. После Lock
            // их никто не читает: LockVault обнуляет vault и перерисовывает вкладку в заблокированное
            // состояние, RefreshOtp/RefreshEntries работают только при открытом vault.
            foreach (var e in Entries)
            {
                e.ClearSecrets(); Secure.Wipe(e.Login); Secure.Wipe(e.Login2);Secure.Wipe(e.LoginUrl);Secure.Wipe(e.AppTarget);Secure.Wipe(e.Notes);
                Secure.Wipe(e.Target); Secure.Wipe(e.Args); Secure.Wipe(e.Window); Secure.Wipe(e.Browser);
            }
            foreach (var o in Otp) { o.ClearSecret(); Secure.Wipe(o.Account); Secure.Wipe(o.Notes); }
            Entries = new List<LoginEntry>();
            Otp = new List<OtpEntry>();
        }

        // ---------------- вспомогательное ----------------

        static byte[] Pbkdf2(string pw, byte[] salt, int iter, int len)
        {
            var bytes = Encoding.UTF8.GetBytes(pw ?? "");
            try {
            using (var k = new System.Security.Cryptography.Rfc2898DeriveBytes(bytes, salt, iter,
                System.Security.Cryptography.HashAlgorithmName.SHA256))
                return k.GetBytes(len);
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }

        static bool FixedEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int d = 0;
            for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
            return d == 0;
        }

        sealed class NullLogger : IStatusLogger
        {
            public void StartLogging(string s, bool b) { }
            public void EndLogging() { }
            public bool SetProgress(uint u) { return true; }
            public bool SetText(string s, LogStatusType t) { return true; }
            public bool ContinueWork() { return true; }
        }
        static readonly IStatusLogger NullLog = new NullLogger();
    }
}

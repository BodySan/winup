using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace WinUp
{
    public enum HelloResult { Ok, Cancelled, Expired, Broken, Unavailable, NotEnabled }

    // Вход по Windows Hello: составной ключ базы (пароль + ключ-файл) зашифрован ключом Windows Hello этого
    // пользователя (провайдер Microsoft Passport). Расшифровать его может только Windows после жеста Hello —
    // лицо, отпечаток или PIN Windows; без жеста ключ из файла не достать.
    // Файл — вне папки WinUp: %LOCALAPPDATA%\WinUp\hello\<папка>.bin. Ключ Hello привязан к этому компьютеру
    // и пользователю, на флешке и в копиях для переноса файл бесполезен, поэтому туда и не попадает.
    // Раз в FullPasswordDays дней нужен полный пароль базы (чтобы его не забыть): срок записан внутри
    // зашифрованной части — продлить его, не расшифровав файл жестом Hello, нельзя.
    static class WindowsHello
    {
        public const int FullPasswordDays = 14;
        const string Ksp = "Microsoft Passport Key Storage Provider";
        const int PadPkcs1 = 2, SilentFlag = 0x40;
        static readonly byte[] FileMagic = Encoding.ASCII.GetBytes("WUH1"), InnerMagic = Encoding.ASCII.GetBytes("WUHI");

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptOpenStorageProvider(out IntPtr prov, string name, int flags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptOpenKey(IntPtr prov, out IntPtr key, string name, int legacySpec, int flags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptSetProperty(IntPtr obj, string prop, byte[] value, int size, int flags);
        [DllImport("ncrypt.dll")] static extern int NCryptEncrypt(IntPtr key, byte[] input, int inSize, IntPtr padding, byte[] output, int outSize, out int result, int flags);
        [DllImport("ncrypt.dll")] static extern int NCryptDecrypt(IntPtr key, byte[] input, int inSize, IntPtr padding, byte[] output, int outSize, out int result, int flags);
        [DllImport("ncrypt.dll")] static extern int NCryptFreeObject(IntPtr obj);
        [DllImport("cryptngc.dll", CharSet = CharSet.Unicode)]
        static extern int NgcGetDefaultDecryptionKeyName(string sid, int reserved1, int reserved2, [MarshalAs(UnmanagedType.LPWStr)] out string keyName);

        static string Dir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinUp", "hello"); } }
        public static string FilePath { get { return Path.Combine(Dir, Program.FolderHash(Paths.Root) + ".bin"); } }
        public static bool Enabled { get { return File.Exists(FilePath); } }

        // Ключ расшифровки Windows Hello текущего пользователя; null — Hello не настроен.
        static string DefaultKeyName()
        {
            try
            {
                string name;
                int rc = NgcGetDefaultDecryptionKeyName(WindowsIdentity.GetCurrent().User.Value, 0, 0, out name);
                return rc == 0 && !string.IsNullOrEmpty(name) ? name : null;
            }
            catch { return null; } // нет cryptngc.dll (старая Windows)
        }

        public static bool Available(out string why)
        {
            why = null;
            if (DefaultKeyName() != null) return true;
            why = "Windows Hello на этом компьютере не настроен.\n\nВключите его: Параметры → Учётные записи → Варианты входа → " +
                  "PIN-код (Windows Hello), распознавание лиц или отпечаток пальца.";
            return false;
        }

        // Срок, после которого нужен полный пароль (открытая копия в заголовке — только для показа; проверяется
        // зашифрованная). null — Hello не включён или файл не читается.
        public static DateTime? NotAfterLocal()
        {
            try
            {
                var b = File.ReadAllBytes(FilePath);
                if (b.Length < 14 || !Same(b, 0, FileMagic)) return null;
                return new DateTime(BitConverter.ToInt64(b, 4), DateTimeKind.Utc).ToLocalTime();
            }
            catch { return null; }
        }

        // Зашифровать ключ базы ключом Hello (без жеста: шифрует открытая часть ключа). Срок — notAfterUtc.
        public static void Seal(byte[] keyMaterial, DateTime notAfterUtc)
        {
            var keyName = DefaultKeyName();
            if (keyName == null) throw new InvalidOperationException("Windows Hello на этом компьютере не настроен.");
            var kek = Vault.Random(64);
            var created = DateTime.UtcNow.Ticks;
            var inner = new byte[4 + 8 + 8 + keyMaterial.Length];
            try
            {
                byte[] enc = WithKey(keyName, true, IntPtr.Zero, null, key =>
                {
                    int size;
                    Check(NCryptEncrypt(key, kek, kek.Length, IntPtr.Zero, null, 0, out size, PadPkcs1), "шифрование");
                    var outb = new byte[size];
                    Check(NCryptEncrypt(key, kek, kek.Length, IntPtr.Zero, outb, outb.Length, out size, PadPkcs1), "шифрование");
                    return Trim(outb, size);
                });
                Buffer.BlockCopy(InnerMagic, 0, inner, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(notAfterUtc.Ticks), 0, inner, 4, 8);
                Buffer.BlockCopy(BitConverter.GetBytes(created), 0, inner, 12, 8);
                Buffer.BlockCopy(keyMaterial, 0, inner, 20, keyMaterial.Length);
                var wrap = KdbxStore.WrapVar(kek, inner);
                var file = new byte[4 + 8 + 2 + enc.Length + wrap.Length];
                Buffer.BlockCopy(FileMagic, 0, file, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(notAfterUtc.Ticks), 0, file, 4, 8);
                Buffer.BlockCopy(BitConverter.GetBytes((ushort)enc.Length), 0, file, 12, 2);
                Buffer.BlockCopy(enc, 0, file, 14, enc.Length);
                Buffer.BlockCopy(wrap, 0, file, 14 + enc.Length, wrap.Length);
                Directory.CreateDirectory(Dir);
                Paths.AtomicWrite(FilePath, file);
            }
            finally
            {
                Array.Clear(kek, 0, kek.Length);
                Array.Clear(inner, 0, inner.Length);
            }
        }

        // Расшифровать ключ базы: Windows показывает окно Hello (владелец — hwnd, текст — message).
        // Вызывать не из потока интерфейса: окно Hello модальное и ждёт пользователя. Возвращённый ключ затирает вызывающий.
        public static byte[] Unseal(IntPtr hwnd, string message, out HelloResult result)
        {
            result = HelloResult.Broken;
            byte[] file;
            try { file = File.ReadAllBytes(FilePath); }
            catch { result = HelloResult.NotEnabled; return null; }
            if (file.Length < 14 + 64 || !Same(file, 0, FileMagic)) return null;
            int encLen = BitConverter.ToUInt16(file, 12);
            if (14 + encLen >= file.Length) return null;
            var enc = Slice(file, 14, encLen);
            var wrap = Slice(file, 14 + encLen, file.Length - 14 - encLen);
            var keyName = DefaultKeyName();
            if (keyName == null) { result = HelloResult.Unavailable; return null; }

            byte[] kek = null, inner = null;
            try
            {
                int rc = 0;
                kek = WithKey(keyName, false, hwnd, message, key =>
                {
                    var outb = new byte[enc.Length];
                    int size;
                    rc = NCryptDecrypt(key, enc, enc.Length, IntPtr.Zero, outb, outb.Length, out size, PadPkcs1);
                    if (rc != 0) { Array.Clear(outb, 0, outb.Length); return null; }
                    var k = Trim(outb, size);
                    Array.Clear(outb, 0, outb.Length);
                    return k;
                });
                if (kek == null)
                {
                    result = IsCancel(rc) ? HelloResult.Cancelled : HelloResult.Broken;
                    LastError = rc;
                    return null;
                }
                inner = KdbxStore.UnwrapVar(kek, wrap);
                if (inner == null || inner.Length < 20 || !Same(inner, 0, InnerMagic)) return null;
                var notAfter = BitConverter.ToInt64(inner, 4);
                var created = BitConverter.ToInt64(inner, 12);
                var now = DateTime.UtcNow.Ticks;
                // Часы переведены назад раньше даты включения — срок не подтверждён, тоже нужен полный пароль.
                if (now > notAfter || now < created - TimeSpan.TicksPerDay) { result = HelloResult.Expired; return null; }
                result = HelloResult.Ok;
                return Slice(inner, 20, inner.Length - 20);
            }
            catch (Exception ex)
            {
                LastError = ex.HResult;
                return null;
            }
            finally
            {
                if (kek != null) Array.Clear(kek, 0, kek.Length);
                if (inner != null) Array.Clear(inner, 0, inner.Length);
            }
        }

        // Код последней ошибки провайдера Hello (для журнала).
        public static int LastError;

        public static void Disable()
        {
            try
            {
                var p = FilePath;
                if (!File.Exists(p)) return;
                File.WriteAllBytes(p, new byte[new FileInfo(p).Length]); // содержимое и так зашифровано; затираем по привычке
                File.Delete(p);
            }
            catch { }
        }

        // Отмена в окне Hello: NTE_USER_CANCELLED, ERROR_CANCELLED, SCARD_W_CANCELLED_BY_USER.
        static bool IsCancel(int rc)
        {
            return rc == unchecked((int)0x80090036) || rc == unchecked((int)0x800704C7) || rc == unchecked((int)0x8010006E);
        }

        static T WithKey<T>(string keyName, bool silent, IntPtr hwnd, string message, Func<IntPtr, T> use)
        {
            IntPtr prov, key;
            Check(NCryptOpenStorageProvider(out prov, Ksp, 0), "провайдер Windows Hello");
            try
            {
                Check(NCryptOpenKey(prov, out key, keyName, 0, silent ? SilentFlag : 0), "ключ Windows Hello");
                try
                {
                    if (!silent)
                    {
                        if (hwnd != IntPtr.Zero)
                        {
                            var h = IntPtr.Size == 8 ? BitConverter.GetBytes(hwnd.ToInt64()) : BitConverter.GetBytes(hwnd.ToInt32());
                            NCryptSetProperty(key, "HWND Handle", h, h.Length, 0);
                        }
                        if (!string.IsNullOrEmpty(message))
                        {
                            var m = Encoding.Unicode.GetBytes(message + "\0");
                            NCryptSetProperty(key, "Use Context", m, m.Length, 0);
                        }
                        // Каждый раз — жест: кэш PIN провайдера не должен открывать базу без участия пользователя.
                        var one = BitConverter.GetBytes(1);
                        NCryptSetProperty(key, "PinCacheIsGestureRequired", one, one.Length, 0);
                    }
                    return use(key);
                }
                finally { NCryptFreeObject(key); }
            }
            finally { NCryptFreeObject(prov); }
        }

        static void Check(int rc, string what)
        {
            if (rc != 0) throw new InvalidOperationException("Windows Hello: " + what + " — ошибка 0x" + rc.ToString("X8"));
        }

        static bool Same(byte[] b, int at, byte[] magic)
        {
            if (b.Length < at + magic.Length) return false;
            for (int i = 0; i < magic.Length; i++) if (b[at + i] != magic[i]) return false;
            return true;
        }

        static byte[] Slice(byte[] b, int at, int n) { var r = new byte[n]; Buffer.BlockCopy(b, at, r, 0, n); return r; }
        static byte[] Trim(byte[] b, int n) { return n == b.Length ? (byte[])b.Clone() : Slice(b, 0, n); }
    }
}

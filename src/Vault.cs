using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace WinUp
{
    public class LoginEntry
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Kind { get; set; }      // "site" | "app"
        public string Target { get; set; }    // URL или путь к exe
        public string Args { get; set; }      // параметры запуска программы
        public string Browser { get; set; }   // "" — как в настройках WinUp
        public string Window { get; set; }    // часть заголовка окна (варианты через |)
        public bool PasskeyBackupEligible { get; set; }
        public bool PasskeyBackedUp { get; set; }
        public string Login { get; set; }
        public string Login2 { get; set; }
        public string AppTarget { get; set; }
        public string LoginUrl { get; set; }
        public string LoginProfile { get; set; }
        public string PasskeyId { get; set; }
        readonly SecretText password = new SecretText();
        public string Password { get { return password.Read(); } set { password.Set(value); } }
        internal T UsePassword<T>(Func<string, T> action) { return password.Use(action); }
        readonly SecretText recoveryCodes = new SecretText();
        public string RecoveryCodes { get { return recoveryCodes.Read(); } set { recoveryCodes.Set(value); } }
        internal T UseRecoveryCodes<T>(Func<string,T> action) { return recoveryCodes.Use(action); }
        internal void ClearSecrets() { password.Clear(); totp.Clear(); recoveryCodes.Clear(); }
        static string CopyText(string value) {return value==null ? null : new string(value.ToCharArray());}
        internal LoginEntry Copy() { return UsePassword(p => UseRecoveryCodes(c => new LoginEntry {
            Id=CopyText(Id), Name=CopyText(Name), Kind=CopyText(Kind), Target=CopyText(Target), AppTarget=CopyText(AppTarget), LoginUrl=CopyText(LoginUrl), LoginProfile=CopyText(LoginProfile), Args=CopyText(Args), Browser=CopyText(Browser), Window=CopyText(Window),
            Login=CopyText(Login), Login2=CopyText(Login2), Password=p, RecoveryCodes=c, PasskeyId=CopyText(PasskeyId),
            PasskeyBackupEligible=PasskeyBackupEligible, PasskeyBackedUp=PasskeyBackedUp,
            AutoEnter=AutoEnter, TwoFa=CopyText(TwoFa), OtpId=CopyText(OtpId), Delay=Delay, Notes=CopyText(Notes)
        })); }
        public bool AutoEnter { get; set; }
        public string TwoFa { get; set; }     // "none" | "ask" | "link" (код из раздела «Коды 2FA»); "totp" — устарело
        public string OtpId { get; set; }     // для "link": какой аккаунт из раздела «Коды 2FA»
        readonly SecretText totp = new SecretText();
        public string Totp { get { return totp.Read(); } set { totp.Set(value); } } // legacy import
        public bool AutoTotp { get; set; }    // устарело (v1.0), читается для перевода в TwoFa
        public int Delay { get; set; }
        public string Notes { get; set; }
        public LoginEntry() { Kind = "site"; Delay = 3; TwoFa = "none"; PasskeyBackupEligible = true; }
    }

    // Аккаунт в разделе «Коды 2FA» — как строка в приложении-аутентификаторе.
    public class OtpEntry
    {
        public string Id { get; set; }
        public string Issuer { get; set; }    // сервис: Google, GitHub...
        public string Account { get; set; }   // логин/почта
        readonly SecretText secret = new SecretText();
        public string Secret { get { return secret.Read(); } set { secret.Set(value); } } // base32
        internal T UseSecret<T>(Func<string, T> action) { return secret.Use(action); }
        internal void ClearSecret() { secret.Clear(); }
        public string Algorithm { get; set; } // SHA1 | SHA256 | SHA512
        public int Digits { get; set; }
        public int Period { get; set; }
        public string Notes { get; set; }
        public OtpEntry() { Algorithm = "SHA1"; Digits = 6; Period = 30; }

        public string Title { get { return string.IsNullOrEmpty(Account) ? (Issuer ?? "") : (Issuer ?? "") + " (" + Account + ")"; } }

        public string Uri()
        {
            var label = System.Uri.EscapeDataString(Issuer ?? "") + (string.IsNullOrEmpty(Account) ? "" : ":" + System.Uri.EscapeDataString(Account));
            var prefix = "otpauth://totp/" + label + "?secret=";
            var suffix = "&issuer=" + System.Uri.EscapeDataString(Issuer ?? "") + "&algorithm=" + Algorithm +
                "&digits=" + Digits.ToString(System.Globalization.CultureInfo.InvariantCulture) + "&period=" + Period.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return UseSecret(s => string.Concat(prefix, s, suffix));
        }
    }

    public class VaultData
    {
        public List<LoginEntry> Entries { get; set; }
        public List<OtpEntry> Otp { get; set; }
        public VaultData() { Entries = new List<LoginEntry>(); Otp = new List<OtpEntry>(); }
    }

    public enum VaultResult { Ok, Wrong, Wiped }

    // Файл vault.dat:
    // v1 (WUV1, старая): "WUV1" | ошибок п.1 | ошибок п.2 | соль1 | хэш п.1 | соль2 | IV | HMAC | шифротекст (ключи из пароля 2).
    // v2 (WUV2): ключ базы (64 байта) завёрнут паролем 2 и кодом восстановления; обёртка = IV | AES-CBC | HMAC.
    // v3 (WUV3, текущая): как v2, плюс в заголовке лежат итерации KDF (P1, P2, кода) и признак ключ-файла.
    //   "WUV3" | ошибок п.1(4) | ошибок п.2(4) | итерации P1(4) | итерации P2(4) | итерации кода(4) | резерв(4)
    //   | соль1(16) | хэш п.1(32) | соль2(16) | обёртка п.2(128) | есть код(1) | соль кода(16) | обёртка кода(128)
    //   | ключ-файл(1) | резерв(16) | IV(16) | HMAC(32) | шифротекст
    //   Ключ-файл: содержимое файла добавляется к паролю 2 при выводе ключа (нужны и пароль, и файл).
    // HMAC тела закрывает всё от соли1 до HMAC и шифротекст; счётчики ошибок, итерации и magic не закрыты —
    // их нужно менять без знания пароля (изменение итераций всё равно ломает вывод ключа).
    // Старые v1/v2 открываются и при первом полном входе пересохраняются в v3 с усиленными итерациями.
    public sealed class Vault
    {
        public const int P1Max = 3, P2Max = 7;
        public const int NewIters = 600000;          // OWASP: PBKDF2-HMAC-SHA256 >= 600 000
        const int Iter1V2 = 60000, Iter2V2 = 100000, IterRcV2 = 100000; // для чтения старых файлов
        const int PinIters = 100000;                 // PIN короткий, но его обёртка живёт только в памяти процесса
        const int MinIters = 1000, MaxIters = 5000000;
        const int OffP1Fails = 4, OffP2Fails = 8, OffP1Salt = 12, OffP1Hash = 28, OffP2Salt = 60;
        const int V1Iv = 76, V1Mac = 92, V1Cipher = 124;
        const int WrapLen = 128;
        const int V2P2Wrap = 76, V2RcFlag = 204, V2RcSalt = 205, V2RcWrap = 221, V2Iv = 349, V2Mac = 365, V2Cipher = 397;
        const int ItP1 = 12, ItP2 = 16, ItRc = 20;                    // v3
        const int Salt1 = 28, Hash1 = 44, Salt2 = 76, P2Wrap = 92, RcFlag = 220, RcSalt = 221, RcWrap = 237;
        const int KfFlag = 365, V3Iv = 382, V3Mac = 398, V3Cipher = 430;
        // Версия KDF обёрток (резерв заголовка v3): 0 — старая (PBKDF2 сразу 64 байта),
        // 1 — текущая (32 байта PBKDF2 + расширение HMAC). Проверка кандидата пароля требует
        // только HMAC-ключ (второй половины), поэтому при 64-байтном выводе атакующий платил
        // за один блок, защитник — за два; при 32-байтном выводе стоимость одинакова (ревью R-2).
        const int KdfP2Ver = 366, KdfRcVer = 367;
        const string RcAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // без 0/O, 1/I
        static readonly byte[] MagicV1 = Encoding.ASCII.GetBytes("WUV1"), MagicV2 = Encoding.ASCII.GetBytes("WUV2"),
                               MagicV3 = Encoding.ASCII.GetBytes("WUV3");

        byte[] p1Salt, p1Hash, p2Salt, p2Wrap, rcSalt, rcWrap, dek;
        byte[] kf;                        // содержимое ключ-файла (в памяти, пока база открыта)
        bool hasRc, kfRequired, needsUpgrade;
        int itersP1, itersP2, itersRc, kdfP2, kdfRc;
        readonly Settings settings;
        public VaultData Data;

        Vault(Settings s) { settings = s; }

        static string FilePath { get { return Paths.VaultFile; } }
        public static bool Exists { get { return File.Exists(FilePath); } }
        // Старая база (WUV1/2/3) существует — ждёт переноса в vault.kdbx при первом полном входе.
        public static bool LegacyExists { get { return File.Exists(FilePath); } }

        // Доступен ли файл базы для записи: счётчики попыток и уничтожение требуют записи.
        // Если файл открыт другой программой или на носителе только для чтения — проверка пароля
        // не выполняется вовсе (fail-closed): без записи счётчик не увеличить и честно не уничтожить.
        public static bool FileWritable()
        {
            try { using (File.Open(FilePath, FileMode.Open, FileAccess.ReadWrite)) return true; }
            catch { return false; }
        }
        public bool HasRecovery { get { return hasRc; } }
        public bool KeyFileRequired { get { return kfRequired; } }
        public bool NeedsUpgrade { get { return needsUpgrade; } }

        // Содержимое ключ-файла открытой базы (для миграции в KdbxStore).
        internal byte[] KeyFileBytes() { return kf; }

        // PIN-сессия: обёртка ключа базы PIN-кодом. Живёт только в памяти работающего приложения —
        // после перезапуска нужен полный вход. 5 неверных вводов — обёртка отбрасывается.
        public sealed class PinSession
        {
            internal byte[] Salt, Wrap;
            internal int Fails;
        }

        static byte[] ReadChecked()
        {
            var b = SafeStorage.ReadBounded(FilePath, 256 * 1024 * 1024);
            if (b.Length < V1Cipher + 16) throw new InvalidDataException("Файл базы повреждён.");
            bool v1 = true, v2 = true, v3 = true;
            for (int i = 0; i < 4; i++) { v1 &= b[i] == MagicV1[i]; v2 &= b[i] == MagicV2[i]; v3 &= b[i] == MagicV3[i]; }
            if (!v1 && !v2 && !v3) throw new InvalidDataException("Это не файл базы WinUp.");
            if (v2 && b.Length < V2Cipher + 16) throw new InvalidDataException("Файл базы повреждён.");
            if (v3 && b.Length < V3Cipher + 16) throw new InvalidDataException("Файл базы повреждён.");
            return b;
        }

        static bool IsV2(byte[] b) { return b[3] == (byte)'2'; }
        static bool IsV3(byte[] b) { return b[3] == (byte)'3'; }

        // Значение итераций из файла ограничиваем: посторонняя правка не должна превращать вход в зависание.
        static int ClampIters(int v) { return v < MinIters ? MinIters : (v > MaxIters ? MaxIters : v); }
        static int ReadIters(byte[] b, int off) { return IsV3(b) ? ClampIters(BitConverter.ToInt32(b, off)) : 0; }

        public static bool FileHasRecovery()
        {
            var b = ReadChecked();
            if (IsV3(b)) return b[RcFlag] == 1;
            return IsV2(b) && b[V2RcFlag] == 1;
        }

        // Нужен ли базе ключ-файл (для показа строки выбора файла при входе).
        public static bool FileUsesKeyFile()
        {
            var b = ReadChecked();
            return IsV3(b) && b[KfFlag] == 1;
        }

        public static int AttemptsLeft(int which)
        {
            var b = ReadChecked();
            return (which == 1 ? P1Max : P2Max) - ReadFails(b, which);
        }

        // Счётчик ошибок лежит в файле вне HMAC (его нужно увеличивать без знания пароля) и может
        // быть изменён снаружи. Диапазон ограничиваем: посторонние значения не должны ломать логику попыток.
        static int ReadFails(byte[] b, int which)
        {
            int fails = BitConverter.ToInt32(b, which == 1 ? OffP1Fails : OffP2Fails);
            int max = which == 1 ? P1Max : P2Max;
            if (fails < 0) return 0;
            if (fails > max - 1) return max - 1;
            return fails;
        }

        static void WriteFails(int which, int value)
        {
            // Счётчик меняем в копии всего файла и пишем атомарно (как Save): прямая запись
            // 4 байт посередине при сбое оставила бы файл битым. Исключение наружу —
            // попытка не расходуется (fail-closed).
            var b = File.ReadAllBytes(FilePath);
            Buffer.BlockCopy(BitConverter.GetBytes(value), 0, b, which == 1 ? OffP1Fails : OffP2Fails, 4);
            Paths.AtomicWrite(FilePath, b);
        }

        static VaultResult Fail(int which, byte[] b, out int left)
        {
            int max = which == 1 ? P1Max : P2Max;
            int fails = ReadFails(b, which) + 1;
            if (fails >= max) { Wipe(); left = 0; return VaultResult.Wiped; }
            WriteFails(which, fails);
            left = max - fails;
            return VaultResult.Wrong;
        }

        public static VaultResult CheckTabPassword(string pw, out int left)
        {
            var b = ReadChecked();
            var iters = IsV3(b) ? ReadIters(b, ItP1) : Iter1V2;
            var salt = IsV3(b) ? Slice(b, Salt1, 16) : Slice(b, OffP1Salt, 16);
            var hash = IsV3(b) ? Slice(b, Hash1, 32) : Slice(b, OffP1Hash, 32);
            var calc = Pbkdf2(pw, salt, iters, 32);
            if (FixedEquals(calc, hash))
            {
                WriteFails(1, 0);
                left = P1Max;
                return VaultResult.Ok;
            }
            return Fail(1, b, out left);
        }

        public static VaultResult Open(string pw, Settings s, out Vault vault, out int left)
        {
            return Open(pw, null, s, out vault, out left);
        }

        // Полный вход: пароль 2 (+ ключ-файл, если база его требует).
        public static VaultResult Open(string pw, string keyFilePath, Settings s, out Vault vault, out int left)
        {
            vault = null;
            var b = ReadChecked();
            var salt2 = IsV3(b) ? Slice(b, Salt2, 16) : Slice(b, OffP2Salt, 16);
            var useKf = IsV3(b) && b[KfFlag] == 1;
            var kfBytes = useKf ? ReadKeyFile(keyFilePath) : null;
            var iters = IsV3(b) ? ReadIters(b, ItP2) : Iter2V2;
            var kek = IsV3(b) ? Kek(pw, kfBytes, salt2, iters, b[KdfP2Ver]) : Pbkdf2(pw, kfBytes, salt2, iters, 64);
            Vault v;
            try
            {
                if (!IsV2(b) && !IsV3(b))
                {
                    if (!FixedEquals(MacV1(Slice(kek, 32, 32), b), Slice(b, V1Mac, 32))) return Fail(2, b, out left);
                    var plain = Decrypt(Slice(kek, 0, 32), Slice(b, V1Iv, 16), b, V1Cipher);
                    // Перевод из v1: новый случайный ключ базы; файл станет v3 при следующем сохранении.
                    var dek = Random(64);
                    v = new Vault(s)
                    {
                        p1Salt = Slice(b, OffP1Salt, 16), p1Hash = Slice(b, OffP1Hash, 32), p2Salt = salt2,
                        p2Wrap = Wrap(kek, dek), hasRc = false, rcSalt = new byte[16], rcWrap = new byte[WrapLen], dek = dek,
                        itersP1 = Iter1V2, itersP2 = Iter2V2, itersRc = IterRcV2, kdfP2 = 0, kdfRc = 0
                    };
                    v.Data = Parse(plain);
                }
                else if (IsV3(b))
                {
                    var dek = Unwrap(kek, Slice(b, P2Wrap, WrapLen));
                    if (dek == null) return Fail(2, b, out left);
                    v = FromBytes(b, dek, s, true);
                    v.kf = kfBytes;
                }
                else
                {
                    var dek = Unwrap(kek, Slice(b, V2P2Wrap, WrapLen));
                    if (dek == null) return Fail(2, b, out left);
                    v = FromBytes(b, dek, s, false);
                }
                WriteFails(2, 0);
                v.needsUpgrade = !IsV3(b) || v.itersP1 < NewIters || v.itersP2 < NewIters;
            }
            finally { Array.Clear(kek, 0, kek.Length); } // ключ обёртки больше не нужен ни при каком выходе
            vault = v; left = P2Max;
            return VaultResult.Ok;
        }

        // Открытие кодом восстановления. Ошибки засчитываются в попытки пароля 2.
        public static VaultResult OpenWithRecovery(string code, Settings s, out Vault vault, out int left)
        {
            vault = null;
            var b = ReadChecked();
            if ((!IsV2(b) && !IsV3(b)) || b[IsV3(b) ? RcFlag : V2RcFlag] != 1)
                throw new InvalidOperationException("У этой базы нет кода восстановления.");
            var iters = IsV3(b) ? ReadIters(b, ItRc) : IterRcV2;
            var rcSaltB = IsV3(b) ? Slice(b, RcSalt, 16) : Slice(b, V2RcSalt, 16);
            var rcWrapB = IsV3(b) ? Slice(b, RcWrap, WrapLen) : Slice(b, V2RcWrap, WrapLen);
            var kek = IsV3(b) ? Kek(NormalizeCode(code), null, rcSaltB, iters, b[KdfRcVer])
                              : Pbkdf2(NormalizeCode(code), rcSaltB, iters, 64);
            var dek = Unwrap(kek, rcWrapB);
            Array.Clear(kek, 0, kek.Length);
            if (dek == null) return Fail(2, b, out left);
            var v = FromBytes(b, dek, s, IsV3(b));
            WriteFails(2, 0);
            v.needsUpgrade = !IsV3(b) || v.itersP2 < NewIters;
            vault = v; left = P2Max;
            return VaultResult.Ok;
        }

        // Разбор v2/v3 после успешной развёртки ключа базы.
        static Vault FromBytes(byte[] b, byte[] dek, Settings s, bool v3)
        {
            if (v3)
            {
                if (!FixedEquals(Mac(Slice(dek, 32, 32), b, Salt1, V3Mac, V3Cipher), Slice(b, V3Mac, 32)))
                    throw new InvalidDataException("Файл базы повреждён или изменён посторонним.");
                var v = new Vault(s)
                {
                    p1Salt = Slice(b, Salt1, 16), p1Hash = Slice(b, Hash1, 32), p2Salt = Slice(b, Salt2, 16),
                    p2Wrap = Slice(b, P2Wrap, WrapLen), hasRc = b[RcFlag] == 1,
                    rcSalt = Slice(b, RcSalt, 16), rcWrap = Slice(b, RcWrap, WrapLen), dek = dek,
                    itersP1 = ReadIters(b, ItP1), itersP2 = ReadIters(b, ItP2), itersRc = ReadIters(b, ItRc),
                    kfRequired = b[KfFlag] == 1, kdfP2 = b[KdfP2Ver], kdfRc = b[KdfRcVer]
                };
                v.Data = Parse(Decrypt(Slice(dek, 0, 32), Slice(b, V3Iv, 16), b, V3Cipher));
                return v;
            }
            if (!FixedEquals(MacV2(Slice(dek, 32, 32), b), Slice(b, V2Mac, 32)))
                throw new InvalidDataException("Файл базы повреждён или изменён посторонним.");
            var old = new Vault(s)
            {
                p1Salt = Slice(b, OffP1Salt, 16), p1Hash = Slice(b, OffP1Hash, 32), p2Salt = Slice(b, OffP2Salt, 16),
                p2Wrap = Slice(b, V2P2Wrap, WrapLen), hasRc = b[V2RcFlag] == 1,
                rcSalt = Slice(b, V2RcSalt, 16), rcWrap = Slice(b, V2RcWrap, WrapLen), dek = dek,
                itersP1 = Iter1V2, itersP2 = Iter2V2, itersRc = IterRcV2
            };
            old.Data = Parse(Decrypt(Slice(dek, 0, 32), Slice(b, V2Iv, 16), b, V2Cipher));
            return old;
        }

        static VaultData Parse(byte[] plain)
        {
            // Промежуточная строка JSON содержит все секреты целиком — затираем сразу после разбора.
            var text = Encoding.UTF8.GetString(plain);
            VaultData d;
            try { d = Json.Read<VaultData>(text) ?? new VaultData(); }
            catch (Exception)
            {
                // Текст ошибки сериализатора может содержать фрагмент данных — не выносим его наружу.
                Secure.Wipe(text);
                Array.Clear(plain, 0, plain.Length);
                throw new InvalidDataException("Файл базы повреждён: данные не разбираются.");
            }
            Secure.Wipe(text);
            Array.Clear(plain, 0, plain.Length);
            if (d.Entries == null) d.Entries = new List<LoginEntry>();
            if (d.Otp == null) d.Otp = new List<OtpEntry>();
            foreach (var e in d.Entries)
            {
                if (string.IsNullOrEmpty(e.TwoFa)) e.TwoFa = e.AutoTotp && !string.IsNullOrEmpty(e.Totp) ? "totp" : "none";
                // Секрет из записи (старые версии) переезжает в раздел «Коды 2FA», запись ссылается на него.
                if (!string.IsNullOrEmpty(e.Totp))
                {
                    var o = d.Otp.Find(x => x.Secret == e.Totp);
                    if (o == null) { o = new OtpEntry { Id = AppStore.NewId(), Issuer = e.Name, Account = e.Login, Secret = e.Totp }; d.Otp.Add(o); }
                    if (e.TwoFa == "totp") { e.TwoFa = "link"; e.OtpId = o.Id; }
                    e.Totp = ""; e.AutoTotp = false;
                }
            }
            return d;
        }

        public static Vault Create(string p1, string p2, Settings s)
        {
            return Create(p1, p2, null, s);
        }

        public static Vault Create(string p1, string p2, string keyFilePath, Settings s)
        {
            var v = new Vault(s) { Data = new VaultData(), dek = Random(64), rcSalt = new byte[16], rcWrap = new byte[WrapLen] };
            v.SetTabPassword(p1);
            v.SetDbPassword(p2, keyFilePath);
            v.Save();
            return v;
        }

        public void SetTabPassword(string p1)
        {
            p1Salt = Random(16); p1Hash = Pbkdf2(p1, p1Salt, NewIters, 32); itersP1 = NewIters;
        }

        // Смена пароля 2 с сохранением текущего состава ключа (в т.ч. ключ-файла, если он был).
        public void SetDbPassword(string p2)
        {
            // Смена пароля 2 ротирует ключ базы (DEK): старые обёртки — прежнего кода
            // восстановления и старые копии файла — к новому DEK больше не подходят (ревью п.4.1).
            dek = Random(64);
            hasRc = false;
            rcSalt = new byte[16]; rcWrap = new byte[WrapLen];
            p2Salt = Random(16);
            var kek = Kek(p2, kf, p2Salt, NewIters, 1);
            p2Wrap = Wrap(kek, dek);
            Array.Clear(kek, 0, kek.Length);
            itersP2 = NewIters;
            kdfP2 = 1; kdfRc = 1;
            kfRequired = kf != null;
        }

        // Смена пароля 2 с явным составом ключа: keyFilePath == null — без ключ-файла, путь — с файлом.
        public void SetDbPassword(string p2, string keyFilePath)
        {
            kf = string.IsNullOrEmpty(keyFilePath) ? null : ReadKeyFile(keyFilePath);
            SetDbPassword(p2);
        }

        public void SetPasswords(string p1, string p2) { SetTabPassword(p1); SetDbPassword(p2); }
        public void SetPasswords(string p1, string p2, string keyFilePath) { SetTabPassword(p1); SetDbPassword(p2, keyFilePath); }

        // Перевод старого файла (v1/v2, слабые итерации) на текущий формат. Нужны оба пароля полного входа.
        public void Upgrade(string p1, string p2)
        {
            p1Salt = Random(16); p1Hash = Pbkdf2(p1, p1Salt, NewIters, 32); itersP1 = NewIters;
            // Обёртка кода восстановления не трогается: DEK тот же, код остаётся действующим
            // со своей старой версией KDF (kdfRc = 0), пока не будет перевыпущен.
            p2Salt = Random(16);
            var kek = Kek(p2, kf, p2Salt, NewIters, 1);
            p2Wrap = Wrap(kek, dek);
            Array.Clear(kek, 0, kek.Length);
            itersP2 = NewIters;
            kdfP2 = 1;
            needsUpgrade = false;
        }

        public bool VerifyDbPassword(string pw)
        {
            var kek = Kek(pw, kf, p2Salt, itersP2, kdfP2);
            var dek = Unwrap(kek, p2Wrap);
            Array.Clear(kek, 0, kek.Length);
            var ok = dek != null;
            // Развёрнутый ключ проверке не нужен — не оставляем его в памяти.
            if (dek != null) Array.Clear(dek, 0, dek.Length);
            return ok;
        }

        // Новый код восстановления; прежний перестаёт работать. Нужно затем сохранить базу.
        public string CreateRecoveryCode()
        {
            var raw = new char[24];
            var bytes = Random(24);
            for (int i = 0; i < 24; i++) raw[i] = RcAlphabet[bytes[i] & 31]; // 32 символа — без перекоса
            var code = new string(raw);
            rcSalt = Random(16);
            var kek = Kek(code, null, rcSalt, NewIters, 1);
            rcWrap = Wrap(kek, dek);
            Array.Clear(kek, 0, kek.Length);
            itersRc = NewIters;
            kdfRc = 1;
            hasRc = true;
            var parts = new List<string>();
            for (int i = 0; i < 24; i += 4) parts.Add(code.Substring(i, 4));
            return string.Join("-", parts);
        }

        public static string NormalizeCode(string code)
        {
            var chars = new char[(code ?? "").Length];
            int count = 0;
            try
            {
                foreach (char c in code ?? "") if (char.IsLetterOrDigit(c)) chars[count++] = char.ToUpperInvariant(c);
                return new string(chars, 0, count);
            }
            finally { Array.Clear(chars, 0, chars.Length); }
        }

        // ---- PIN: быстрый вход вместо паролей, обёртка живёт только в памяти процесса ----

        public PinSession MakePin(string pinCode)
        {
            var salt = Random(16);
            var kek = Kek(pinCode, null, salt, PinIters, 1);
            var w = Wrap(kek, dek);
            Array.Clear(kek, 0, kek.Length);
            return new PinSession { Salt = salt, Wrap = w };
        }

        // Открытие базы по PIN. Попытки файла не расходуются; неверный PIN — просто VaultResult.Wrong.
        public static VaultResult OpenWithPin(string pinCode, PinSession pin, Settings s, out Vault vault)
        {
            vault = null;
            var b = ReadChecked();
            var kek = Kek(pinCode, null, pin.Salt, PinIters, 1);
            var dek = Unwrap(kek, pin.Wrap);
            Array.Clear(kek, 0, kek.Length);
            if (dek == null) return VaultResult.Wrong;
            Vault v;
            if (IsV3(b)) v = FromBytes(b, dek, s, true);
            else if (IsV2(b)) v = FromBytes(b, dek, s, false);
            else throw new InvalidDataException("Старый формат базы: сначала откройте её паролями.");
            v.needsUpgrade = !IsV3(b) || v.itersP2 < NewIters || v.itersP1 < NewIters;
            vault = v;
            return VaultResult.Ok;
        }

        public void Save()
        {
            // Сериализованная строка содержит все секреты целиком — затираем сразу после шифрования.
            var json = Json.Write(Data, false);
            var plain = Encoding.UTF8.GetBytes(json);
            Secure.Wipe(json);
            var iv = Random(16);
            var cipher = Encrypt(Slice(dek, 0, 32), iv, plain);
            Array.Clear(plain, 0, plain.Length);

            var b = new byte[V3Cipher + cipher.Length];
            Buffer.BlockCopy(MagicV3, 0, b, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(itersP1), 0, b, ItP1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(itersP2), 0, b, ItP2, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(itersRc), 0, b, ItRc, 4);
            Buffer.BlockCopy(p1Salt, 0, b, Salt1, 16);
            Buffer.BlockCopy(p1Hash, 0, b, Hash1, 32);
            Buffer.BlockCopy(p2Salt, 0, b, Salt2, 16);
            Buffer.BlockCopy(p2Wrap, 0, b, P2Wrap, WrapLen);
            b[RcFlag] = (byte)(hasRc ? 1 : 0);
            Buffer.BlockCopy(rcSalt, 0, b, RcSalt, 16);
            Buffer.BlockCopy(rcWrap, 0, b, RcWrap, WrapLen);
            b[KfFlag] = (byte)(kfRequired ? 1 : 0);
            b[KdfP2Ver] = (byte)kdfP2;
            b[KdfRcVer] = (byte)kdfRc;
            Buffer.BlockCopy(iv, 0, b, V3Iv, 16);
            Buffer.BlockCopy(cipher, 0, b, V3Cipher, cipher.Length);
            Buffer.BlockCopy(Mac(Slice(dek, 32, 32), b, Salt1, V3Mac, V3Cipher), 0, b, V3Mac, 32);
            needsUpgrade = false;

            Paths.AtomicWrite(FilePath, b);
            Backup.Copy(FilePath, "vault", ".dat", settings);
        }

        public void Lock()
        {
            if (dek != null) Array.Clear(dek, 0, dek.Length);
            // Байты ключ-файла — половина составного ключа полного входа, затираем как DEK.
            if (kf != null) { Array.Clear(kf, 0, kf.Length); kf = null; }
            // Затираем строки секретов в куче: .NET-строки нельзя обнулить обычным путём,
            // но прямая перезапись символов (как в KeePass) убирает их из памяти.
            if (Data != null)
            {
                foreach (var e in Data.Entries)
                {
                    e.ClearSecrets(); Secure.Wipe(e.Login); Secure.Wipe(e.Notes);
                    Secure.Wipe(e.Target); Secure.Wipe(e.Args); Secure.Wipe(e.Window);
                    e.Password = e.Login = e.Notes = e.Totp = "";
                }
                foreach (var o in Data.Otp) { o.ClearSecret(); Secure.Wipe(o.Notes); o.Notes = ""; }
            }
            Data = null;
        }

        // Уничтожение: перезапись случайными байтами и удаление (сам файл, .bak, .tmp).
        // Резервные копии в папке резерва не трогаются — это путь восстановления для владельца.
        public static void Wipe()
        {
            foreach (var f in new[] { FilePath, FilePath + ".bak", FilePath + ".tmp" })
            {
                string error;
                Secure.WipeFile(f, out error);
            }
        }

        // ---- примитивы ----

        internal static byte[] Wrap(byte[] kek, byte[] key)
        {
            var iv = Random(16);
            var ct = Encrypt(Slice(kek, 0, 32), iv, key);
            var w = new byte[WrapLen];
            Buffer.BlockCopy(iv, 0, w, 0, 16);
            Buffer.BlockCopy(ct, 0, w, 16, ct.Length);
            using (var h = new HMACSHA256(Slice(kek, 32, 32))) Buffer.BlockCopy(h.ComputeHash(w, 0, 96), 0, w, 96, 32);
            return w;
        }

        internal static byte[] Unwrap(byte[] kek, byte[] w)
        {
            byte[] mac;
            using (var h = new HMACSHA256(Slice(kek, 32, 32))) mac = h.ComputeHash(w, 0, 96);
            if (!FixedEquals(mac, Slice(w, 96, 32))) return null;
            return Decrypt(Slice(kek, 0, 32), Slice(w, 0, 16), Slice(w, 16, 80), 0);
        }

        static byte[] Encrypt(byte[] key, byte[] iv, byte[] plain)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key; aes.IV = iv;
                using (var e = aes.CreateEncryptor()) return e.TransformFinalBlock(plain, 0, plain.Length);
            }
        }

        static byte[] Decrypt(byte[] key, byte[] iv, byte[] buf, int off)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key; aes.IV = iv;
                using (var d = aes.CreateDecryptor()) return d.TransformFinalBlock(buf, off, buf.Length - off);
            }
        }

        static byte[] MacV1(byte[] key, byte[] b) { return Mac(key, b, OffP1Salt, V1Mac, V1Cipher); }
        static byte[] MacV2(byte[] key, byte[] b) { return Mac(key, b, OffP1Salt, V2Mac, V2Cipher); }

        static byte[] Mac(byte[] key, byte[] b, int from, int macOff, int cipherOff)
        {
            using (var h = new HMACSHA256(key))
            {
                h.TransformBlock(b, from, macOff - from, null, 0);
                h.TransformFinalBlock(b, cipherOff, b.Length - cipherOff);
                return h.Hash;
            }
        }

        static byte[] Pbkdf2(string pw, byte[] salt, int iter, int len)
        {
            var input = Encoding.UTF8.GetBytes(pw ?? "");
            try { using (var k = new Rfc2898DeriveBytes(input, salt, iter, HashAlgorithmName.SHA256))
                return k.GetBytes(len);
            }
            finally { Array.Clear(input, 0, input.Length); }
        }

        // Пароль + содержимое ключ-файла как единый вход KDF: для входа нужны и то, и другое.
        static byte[] Pbkdf2(string pw, byte[] keyFile, byte[] salt, int iter, int len)
        {
            if (keyFile == null || keyFile.Length == 0) return Pbkdf2(pw, salt, iter, len);
            var pwBytes = Encoding.UTF8.GetBytes(pw ?? "");
            var input = new byte[pwBytes.Length + keyFile.Length];
            Buffer.BlockCopy(pwBytes, 0, input, 0, pwBytes.Length);
            Buffer.BlockCopy(keyFile, 0, input, pwBytes.Length, keyFile.Length);
            try { using (var k = new Rfc2898DeriveBytes(input, salt, iter, HashAlgorithmName.SHA256))
                return k.GetBytes(len);
            }
            finally { Array.Clear(pwBytes, 0, pwBytes.Length); Array.Clear(input, 0, input.Length); }
        }

        // Вход KDF версии 1: при ключ-файле пароль подмешивается через HMAC от содержимого файла —
        // границы «пароль|файл» однозначны, склейка без разделителя не допускается (ревью R-7).
        static byte[] KdfInput(string pw, byte[] keyFile)
        {
            var pwBytes = Encoding.UTF8.GetBytes(pw ?? "");
            if (keyFile == null || keyFile.Length == 0) return pwBytes;
            try { using (var h = new HMACSHA256(keyFile)) return h.ComputeHash(pwBytes); }
            finally { Array.Clear(pwBytes, 0, pwBytes.Length); }
        }

        // Ключ обёртки DEK. v0 (старые файлы v3): PBKDF2 сразу 64 байта.
        // v1: 32 байта PBKDF2 (один блок — проверка кандидата и у атакующего, и у защитника
        // стоит одинаково), половины для AES и HMAC — расширение HMAC с разными метками.
        internal static byte[] Kek(string pw, byte[] keyFile, byte[] salt, int iter, int kdfVer)
        {
            if (kdfVer == 0) return Pbkdf2(pw, keyFile, salt, iter, 64);
            var input = KdfInput(pw, keyFile);
            byte[] k;
            try { k = Pbkdf2raw(input, salt, iter, 32); }
            finally { Array.Clear(input, 0, input.Length); }
            var kek = new byte[64];
            try
            {
            using (var h = new HMACSHA256(k))
            {
                Buffer.BlockCopy(h.ComputeHash(Encoding.ASCII.GetBytes("WinUp-kek-enc")), 0, kek, 0, 32);
                Buffer.BlockCopy(h.ComputeHash(Encoding.ASCII.GetBytes("WinUp-kek-mac")), 0, kek, 32, 32);
            }
            return kek;
            }
            finally { Array.Clear(k, 0, k.Length); }
        }

        static byte[] Pbkdf2raw(byte[] input, byte[] salt, int iter, int len)
        {
            using (var k = new Rfc2898DeriveBytes(input, salt, iter, HashAlgorithmName.SHA256))
                return k.GetBytes(len);
        }

        static byte[] ReadKeyFile(string path)
        {
            if (string.IsNullOrEmpty(path)) throw new FileNotFoundException("Ключ-файл не выбран.");
            if (!File.Exists(path)) throw new FileNotFoundException("Ключ-файл не найден: " + path);
            var b = File.ReadAllBytes(path);
            if (b.Length == 0) throw new InvalidDataException("Ключ-файл пуст.");
            if (b.Length > 4 * 1024 * 1024) throw new InvalidDataException("Ключ-файл слишком большой (максимум 4 МБ).");
            return b;
        }

        internal static byte[] Random(int n)
        {
            var r = new byte[n];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(r);
            return r;
        }

        static byte[] Slice(byte[] b, int off, int len)
        {
            var r = new byte[len];
            Buffer.BlockCopy(b, off, r, 0, len);
            return r;
        }

        static bool FixedEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int d = 0;
            for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
            return d == 0;
        }
    }

    // Затирание строк в памяти (секреты после блокировки не должны остаться в куче).
    static class Secure
    {
        public static byte[] Utf8AndClear(StringBuilder builder, bool bom = false)
        {
            var text = builder.ToString();
            byte[] raw = null;
            try
            {
                raw = Encoding.UTF8.GetBytes(text);
                if (!bom) { var result = raw; raw = null; return result; }
                var prefix = new UTF8Encoding(true).GetPreamble();
                var output = new byte[prefix.Length + raw.Length];
                Buffer.BlockCopy(prefix, 0, output, 0, prefix.Length);
                Buffer.BlockCopy(raw, 0, output, prefix.Length, raw.Length);
                return output;
            }
            finally
            {
                Secure.Wipe(text);
                if (raw != null) Array.Clear(raw, 0, raw.Length);
                for (int i = 0; i < builder.Length; i++) builder[i] = '\0';
                builder.Clear();
            }
        }
        // Перезапись случайными байтами и удаление. Лучшее усилие: на SSD, в теневых копиях и облачных папках
        // прежние блоки могут остаться — поэтому старые копии с прежним паролем лучше не плодить вовсе.
        public static bool WipeFile(string path, out string error)
        {
            error = null;
            try
            {
                if (!File.Exists(path)) return true;
                SafeStorage.WipeFile(path);
                return !File.Exists(path);
            }
            catch (Exception e) { error = e.Message; return false; }
        }

        public static void Wipe(string s)
        {
            if (string.IsNullOrEmpty(s)) return;
            // Shared literals belong to the runtime, never to a secret scope.
            if (ReferenceEquals(string.IsInterned(s), s)) return;
            unsafe
            {
                fixed (char* p = s)
                {
                    for (int i = 0; i < s.Length; i++) p[i] = '\0';
                }
            }
        }

        // После затирания строк: сборка мусора + обнуляющая аллокация. CLR обнуляет память при
        // выделении, поэтому прокрутка кучи перезаписывает освободившиеся копии секретов нулями —
        // след в дампе памяти работающего заблокированного приложения уменьшается.
        public static void ScrubHeap()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            var loh = new byte[32][];                     // большая куча: буферы сохранения базы
            for (int i = 0; i < loh.Length; i++) { loh[i] = new byte[1 << 20]; loh[i][0] = 1; }
            for (int i = 0; i < 8192; i++) { var b = new byte[1024]; b[0] = 1; }   // малая куча: строки
        }
    }

    static class Totp
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        // Принимает base32-секрет или ссылку otpauth://...?secret=...
        public static string Normalize(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return "";
            string encoded = null, decoded = null;
            try
            {
            if (s.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                var m = System.Text.RegularExpressions.Regex.Match(s, @"[?&]secret=([^&]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                encoded = m.Success ? m.Groups[1].Value : "";
                decoded = Uri.UnescapeDataString(encoded);
                s = decoded;
            }
            int start = 0, end = s.Length;
            while (start < end && char.IsWhiteSpace(s[start])) start++;
            while (end > start && (char.IsWhiteSpace(s[end-1]) || s[end-1] == '=')) end--;
            var chars = new char[end - start]; int count = 0;
            try
            {
                for (int i = start; i < end; i++) if (s[i] != ' ' && s[i] != '-') chars[count++] = char.ToUpperInvariant(s[i]);
                return new string(chars, 0, count);
            }
            finally { Array.Clear(chars, 0, chars.Length); }
            }
            finally { Secure.Wipe(encoded); Secure.Wipe(decoded); }
        }

        public static byte[] Base32(string s)
        {
            s = Normalize(s);
            var bytes = new List<byte>();
            try
            {
            int buf = 0, bits = 0;
            foreach (char c in s)
            {
                int v = Alphabet.IndexOf(c);
                if (v < 0) throw new FormatException("Недопустимый символ в секрете 2FA: " + c);
                buf = (buf << 5) | v; bits += 5;
                if (bits >= 8) { bytes.Add((byte)(buf >> (bits - 8))); bits -= 8; buf &= (1 << bits) - 1; }
            }
            if (bytes.Count == 0) throw new FormatException("Пустой секрет 2FA.");
            return bytes.ToArray();
            }
            finally { Secure.Wipe(s); for (int i=0; i<bytes.Count; i++) bytes[i]=0; bytes.Clear(); }
        }

        public static string Code(string secret) { return Code(secret, DateTimeOffset.UtcNow.ToUnixTimeSeconds()); }
        public static string Code(string secret, long unixTime) { return Code(secret, "SHA1", 6, 30, unixTime); }
        public static string Code(OtpEntry o) { return o.UseSecret(s => Code(s, o.Algorithm, o.Digits, o.Period, DateTimeOffset.UtcNow.ToUnixTimeSeconds())); }

        public static string Code(string secret, string algorithm, int digits, int period, long unixTime)
        {
            if (period <= 0) period = 30;
            if (digits < 6 || digits > 8) digits = 6;
            var msg = BitConverter.GetBytes(unixTime / period);
            if (BitConverter.IsLittleEndian) Array.Reverse(msg);
            byte[] h;
            var key = Base32(secret);
            try { using (var hmac = Hmac(algorithm, key)) h = hmac.ComputeHash(msg); }
            finally { Array.Clear(key, 0, key.Length); }
            int o = h[h.Length - 1] & 0x0f;
            int bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
            return (bin % (int)Math.Pow(10, digits)).ToString("D" + digits);
        }

        static HMAC Hmac(string algorithm, byte[] key)
        {
            switch ((algorithm ?? "SHA1").ToUpperInvariant().Replace("-", ""))
            {
                case "SHA256": return new HMACSHA256(key);
                case "SHA512": return new HMACSHA512(key);
                default: return new HMACSHA1(key);
            }
        }

        public static string ToBase32(byte[] data)
        {
            var sb = new StringBuilder();
            int buf = 0, bits = 0;
            foreach (var b in data)
            {
                buf = (buf << 8) | b; bits += 8;
                while (bits >= 5) { sb.Append(Alphabet[(buf >> (bits - 5)) & 31]); bits -= 5; }
            }
            if (bits > 0) sb.Append(Alphabet[(buf << (5 - bits)) & 31]);
            return sb.ToString();
        }

        public static int SecondsLeft { get { return SecondsLeftFor(30); } }
        public static int SecondsLeftFor(int period)
        {
            if (period <= 0) period = 30;
            return period - (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() % period);
        }
    }

    // Генератор паролей на криптостойком ГСЧ.
    static class PasswordGen
    {
        public const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", Lower = "abcdefghijklmnopqrstuvwxyz",
                            Digits = "0123456789", Symbols = "!@#$%^&*()-_=+[]{};:,.?/~";
        const string Ambiguous = "O0oIl1|";

        public static string Make(int length, bool upper, bool lower, bool digits, bool symbols, bool noAmbiguous)
        {
            var sets = new List<string>();
            Action<bool, string> add = (on, set) =>
            {
                if (!on) return;
                if (noAmbiguous) set = new string(Array.FindAll(set.ToCharArray(), c => Ambiguous.IndexOf(c) < 0));
                sets.Add(set);
            };
            add(upper, Upper); add(lower, Lower); add(digits, Digits); add(symbols, Symbols);
            if (sets.Count == 0) throw new ArgumentException("Выберите хотя бы один вид символов.");
            length = Math.Max(length, sets.Count);
            var all = string.Concat(sets);
            var chars = new char[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                // По одному символу каждого выбранного вида, остальное — из общего набора, затем перемешать.
                for (int i = 0; i < length; i++) chars[i] = i < sets.Count ? sets[i][Next(rng, sets[i].Length)] : all[Next(rng, all.Length)];
                for (int i = length - 1; i > 0; i--) { int j = Next(rng, i + 1); var t = chars[i]; chars[i] = chars[j]; chars[j] = t; }
            }
            try { return new string(chars); }
            finally { Array.Clear(chars, 0, chars.Length); }
        }

        // Стойкость случайного пароля: длина · log2(размер набора) (условие «по символу каждого вида» почти не влияет).
        public static double Bits(int length, bool upper, bool lower, bool digits, bool symbols, bool noAmbiguous)
        {
            int pool = 0;
            Func<bool, string, int> n = (on, set) => !on ? 0 : noAmbiguous ? set.Count(c => Ambiguous.IndexOf(c) < 0) : set.Length;
            pool = n(upper, Upper) + n(lower, Lower) + n(digits, Digits) + n(symbols, Symbols);
            return pool < 2 ? 0 : Math.Max(length, 1) * Math.Log(pool, 2);
        }

        // Равномерное число 0..max-1 (отбрасывание, без перекоса по модулю).
        internal static int Next(RandomNumberGenerator rng, int max)
        {
            var buf = new byte[4];
            uint limit = uint.MaxValue - uint.MaxValue % (uint)max;
            uint x;
            do { rng.GetBytes(buf); x = BitConverter.ToUInt32(buf, 0); } while (x >= limit);
            return (int)(x % (uint)max);
        }
    }
}

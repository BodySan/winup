using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace WinUp
{
    // Экспорт паролей в отдельные файлы, которые читаются без WinUp.
    static class Export
    {
        // Exports are new files. A failed write or a racing target must never
        // truncate an earlier backup; commit only a fully flushed temporary file.
        internal static void WriteFresh(string path, Action<FileStream> write)
        {
            path = Path.GetFullPath(path);
            SafePaths.NoReparseParents(path);
            string parent = Path.GetDirectoryName(path);
            using (var directories = SourceLease.HoldDirectories(parent))
            {
                if (File.Exists(path) || Directory.Exists(path)) throw new IOException("Файл экспорта уже существует. Выберите новое имя.");
                string temporary = Path.Combine(parent, ".winup-export-" + Guid.NewGuid().ToString("N"));
                try
                {
                    using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        write(output);
                        output.Flush(true);
                    }
                    File.Move(temporary, path);
                }
                finally { File.Delete(temporary); }
            }
        }

        internal static void CopyEncryptedDatabase(string source, string destination)
        {
            using (var lease = SourceLease.Acquire(source, false))
                WriteFresh(destination, output => { using (var input = File.OpenRead(source)) input.CopyTo(output); });
        }

        // Ключ для экспорта: 24 символа без похожих (0/O, 1/l/I), удобно переписать вручную.
        public static string NewKey()
        {
            return PasswordGen.Make(24, true, true, true, false, true);
        }

        public static string KeyProblem(string key)
        {
            if (key == null || key.Length < 12) return "Ключ — не короче 12 символов.";
            foreach (char c in key)
                if (c < 33 || c > 126) return "В ключе — только латинские буквы, цифры и обычные символы (без пробелов и кириллицы): " +
                                              "иначе архив может не открыться в 7-Zip/WinRAR.";
            if (Strength.Bits(key) < Strength.MinForVault) return "Ключ слишком простой. Используйте сгенерированный ключ или длинный случайный пароль.";
            return null;
        }

        static string TwoFaName(LoginEntry e)
        {
            return e.TwoFa == "ask" ? "код при входе" : e.TwoFa == "link" ? "из «Коды 2FA»" : "нет";
        }

        static OtpEntry Linked(LoginEntry e, List<OtpEntry> otps)
        {
            return e.TwoFa == "link" && otps != null ? otps.Find(o => o.Id == e.OtpId) : null;
        }

        // Ссылки otpauth:// — их понимают почти все приложения-аутентификаторы (импорт обратно в телефон).
        public static byte[] OtpLinks(List<OtpEntry> otps)
        {
            var sb = new StringBuilder();
            foreach (var o in otps)
            {
                var uri = o.Uri();
                try { sb.Append(uri).Append("\r\n"); }
                finally { Secure.Wipe(uri); }
            }
            return Secure.Utf8AndClear(sb);
        }

        // Таблица для Excel: UTF-8 с BOM, разделитель «;».
        public static byte[] Csv(List<LoginEntry> entries, List<OtpEntry> otps)
        {
            var sb = new StringBuilder();
            Action<string> q = v =>
            {
                sb.Append('"');
                // CSV is for viewing in spreadsheet software. Quoting alone does
                // not stop formulas supplied through a site name/login/secret.
                if (CsvFormula(v)) sb.Append('\'');
                foreach (char c in v ?? "") { if (c == '"') sb.Append('"'); sb.Append(c); }
                sb.Append('"');
            };
            sb.Append("Название;Тип;Адрес или программа;Логин;Пароль;2FA;Секрет 2FA;Заметка;Дополнительный логин;Приложение;Резервные коды;Ключ доступа (ID);Дополнительные поля (JSON)\r\n");
            foreach (var e in entries)
            {
                if (e.Kind == "passkey") continue;
                q(e.Name); sb.Append(';'); q(e.Kind == "app" ? "программа" : "сайт"); sb.Append(';');
                q(e.Target); sb.Append(';'); q(e.Login); sb.Append(';');
                e.UsePassword(pw => { q(pw); return 0; }); sb.Append(';'); q(TwoFaName(e)); sb.Append(';');
                var otp = Linked(e, otps);
                if (otp == null) q(""); else otp.UseSecret(s => { q(s); return 0; });
                sb.Append(';'); q(e.Notes); sb.Append(';'); q(e.Login2); sb.Append(';'); q(e.AppTarget); sb.Append(';');
                e.UseRecoveryCodes(c => { q(c); return 0; }); sb.Append(';'); q(e.PasskeyId); sb.Append(';');
                var fields=new Dictionary<string,string>();string json=null;try{foreach(var field in e.CustomFields)fields.Add(field.Name,field.Value);json=new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(fields);q(json);}finally{Secure.Wipe(json);foreach(var value in fields.Values)Secure.Wipe(value);}
                sb.Append("\r\n");
            }
            return Secure.Utf8AndClear(sb, true);
        }

        static bool CsvFormula(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            if (value[0] == '\t' || value[0] == '\r' || value[0] == '\n') return true;
            int first = 0;
            while (first < value.Length && (char.IsWhiteSpace(value[first]) || value[first] == '\uFEFF')) first++;
            return first < value.Length && "=+-@＝＋－＠".IndexOf(value[first]) >= 0;
        }

        public static byte[] Text(List<LoginEntry> entries, List<OtpEntry> otps)
        {
            var sb = new StringBuilder();
            sb.Append("Пароли из WinUp, выгружено " + DateTime.Now.ToString("dd.MM.yyyy HH:mm") + "\r\n\r\n");
            foreach (var e in entries)
            {
                if (e.Kind == "passkey") continue;
                sb.Append("== " + e.Name + " ==\r\n");
                if (!string.IsNullOrEmpty(e.Target)) sb.Append((e.Kind == "app" ? "Программа: " : "Сайт: ") + e.Target + "\r\n");
                sb.Append("Логин: " + e.Login + "\r\n");
                if(!string.IsNullOrEmpty(e.Login2)) sb.Append("Дополнительный логин: "+e.Login2+"\r\n");
                if(!string.IsNullOrEmpty(e.AppTarget)) sb.Append("Приложение: "+e.AppTarget+"\r\n");
                e.UsePassword(pw => { sb.Append("Пароль: ").Append(pw).Append("\r\n"); return 0; });
                e.UseRecoveryCodes(c => { if(!string.IsNullOrWhiteSpace(c)) sb.Append("Резервные коды:\r\n").Append(c).Append("\r\n"); return 0; });
                if(!string.IsNullOrEmpty(e.PasskeyId)) sb.Append("Ключ доступа: "+e.PasskeyId+" (сам ключ сохраняется в экспорте KDBX)\r\n");
                if (Linked(e, otps) != null) Linked(e, otps).UseSecret(s => { sb.Append("Секрет 2FA: ").Append(s).Append("\r\n"); return 0; });
                if (!string.IsNullOrEmpty(e.Notes)) sb.Append("Заметка: " + e.Notes + "\r\n");
                foreach(var field in e.CustomFields)field.UseValue(value=>{sb.Append(field.Name).Append(": ").Append(value).Append("\r\n");return 0;});
                sb.Append("\r\n");
            }
            if (otps != null && otps.Count > 0)
            {
                sb.Append("===== Коды 2FA =====\r\n");
                foreach (var o in otps) o.UseSecret(s =>
                {
                    sb.Append(o.Title).Append("\r\n  ключ: ").Append(s).Append(" (").Append(o.Algorithm)
                        .Append(", ").Append(o.Digits).Append(" цифр, ").Append(o.Period).Append(" с)\r\n"); return 0;
                });
            }
            return Secure.Utf8AndClear(sb, true);
        }

        // ---------- .zip с шифрованием AES-256 (формат WinZip AE-2: открывают 7-Zip, WinRAR) ----------

        public static void ZipAes(string path, List<KeyValuePair<string, byte[]>> files, string password)
        {
            var pw = Encoding.UTF8.GetBytes(password);
            try
            {
            ushort time, date;
            DosTime(DateTime.Now, out time, out date);
            WriteFresh(path, fs =>
            {
                using (var w = new BinaryWriter(fs, Encoding.UTF8, true))
                {
                var central = new MemoryStream();
                var cw = new BinaryWriter(central);
                foreach (var f in files)
                {
                    var name = Encoding.UTF8.GetBytes(f.Key);
                    var salt = new byte[16];
                    using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);
                    byte[] dk;
                    using (var k = new Rfc2898DeriveBytes(pw, salt, 1000)) dk = k.GetBytes(66); // HMAC-SHA1, как в спецификации
                    var encKey = dk.Take(32).ToArray();
                    var authKey = dk.Skip(32).Take(32).ToArray();
                    var verifier = dk.Skip(64).Take(2).ToArray();
                    try
                    {
                    var enc = AesCtr(encKey, f.Value);
                    byte[] mac;
                    using (var h = new HMACSHA1(authKey)) mac = h.ComputeHash(enc);
                    uint compSize = (uint)(salt.Length + 2 + enc.Length + 10);
                    // Дополнительное поле AES: id 0x9901, версия AE-2, "AE", AES-256, метод «без сжатия».
                    var extra = new byte[] { 0x01, 0x99, 7, 0, 2, 0, (byte)'A', (byte)'E', 3, 0, 0 };
                    uint offset = (uint)fs.Position;
                    const ushort flags = 0x0001 | 0x0800; // зашифровано | имена в UTF-8

                    w.Write(0x04034b50u); w.Write((ushort)51); w.Write(flags); w.Write((ushort)99);
                    w.Write(time); w.Write(date); w.Write(0u); w.Write(compSize); w.Write((uint)f.Value.Length);
                    w.Write((ushort)name.Length); w.Write((ushort)extra.Length); w.Write(name); w.Write(extra);
                    w.Write(salt); w.Write(verifier); w.Write(enc); w.Write(mac, 0, 10);

                    cw.Write(0x02014b50u); cw.Write((ushort)51); cw.Write((ushort)51); cw.Write(flags); cw.Write((ushort)99);
                    cw.Write(time); cw.Write(date); cw.Write(0u); cw.Write(compSize); cw.Write((uint)f.Value.Length);
                    cw.Write((ushort)name.Length); cw.Write((ushort)extra.Length); cw.Write((ushort)0);
                    cw.Write((ushort)0); cw.Write((ushort)0); cw.Write(0u); cw.Write(offset);
                    cw.Write(name); cw.Write(extra);
                    }
                    finally
                    {
                        Array.Clear(dk, 0, dk.Length); Array.Clear(encKey, 0, encKey.Length);
                        Array.Clear(authKey, 0, authKey.Length); Array.Clear(verifier, 0, verifier.Length);
                    }
                }
                cw.Flush();
                uint cdStart = (uint)fs.Position;
                var cd = central.ToArray();
                w.Write(cd);
                w.Write(0x06054b50u); w.Write((ushort)0); w.Write((ushort)0);
                w.Write((ushort)files.Count); w.Write((ushort)files.Count);
                w.Write((uint)cd.Length); w.Write(cdStart); w.Write((ushort)0);
                }
            });
            }
            finally
            {
                Array.Clear(pw, 0, pw.Length);
                // This API consumes the plaintext payloads, including on failure.
                foreach (var file in files) if (file.Value != null) Array.Clear(file.Value, 0, file.Value.Length);
            }
        }

        // AES-CTR со счётчиком little-endian, начиная с 1 (как в WinZip AES).
        static byte[] AesCtr(byte[] key, byte[] data)
        {
            var output = new byte[data.Length];
            var ctr = new byte[16];
            var ks = new byte[16];
            try
            {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key;
                using (var e = aes.CreateEncryptor())
                    for (int i = 0; i < data.Length; i += 16)
                    {
                        for (int j = 0; j < 16; j++) if (++ctr[j] != 0) break;
                        e.TransformBlock(ctr, 0, 16, ks, 0);
                        for (int j = 0; j < 16 && i + j < data.Length; j++) output[i + j] = (byte)(data[i + j] ^ ks[j]);
                    }
            }
            return output;
            }
            finally { Array.Clear(ks, 0, ks.Length); Array.Clear(ctr, 0, ctr.Length); }
        }

        static void DosTime(DateTime t, out ushort time, out ushort date)
        {
            time = (ushort)((t.Hour << 11) | (t.Minute << 5) | (t.Second / 2));
            date = (ushort)(((t.Year - 1980) << 9) | (t.Month << 5) | t.Day);
        }
    }
}

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace WinUp
{
    // Импорт аккаунтов 2FA из других приложений. Понимает:
    //  • otpauth-migration://offline?data=... — экспорт Google Authenticator (ссылка из его QR-кода);
    //  • otpauth://totp/... — стандартные ссылки (Ente Auth, FreeOTP+, Bitwarden, текстовые экспорты Aegis и др.);
    //  • JSON-экспорты без шифрования: Aegis, 2FAS (.2fas), andOTP, Bitwarden.
    static class OtpImport
    {
        internal const int MaxInput = 8 * 1024 * 1024;
        public static List<OtpEntry> Parse(string text, List<string> warnings)
        {
            var result = new List<OtpEntry>();
            text = text ?? "";
            if (text.Length > MaxInput) { warnings.Add("Экспорт 2FA превышает допустимый размер 8 МБ. Разделите его на несколько файлов."); return result; }

            foreach (Match m in Regex.Matches(text, @"otpauth-migration://offline\?data=([^\s""'<>&]+)", RegexOptions.IgnoreCase))
            {
                try { result.AddRange(FromGoogle(m.Groups[1].Value, warnings)); }
                catch (Exception ex) { warnings.Add("Ссылка Google Authenticator не разобрана: " + ex.Message); }
            }

            foreach (Match m in Regex.Matches(text, @"otpauth://[^\s""'<>,;]+", RegexOptions.IgnoreCase))
            {
                if (m.Value.StartsWith("otpauth-migration", StringComparison.OrdinalIgnoreCase)) continue;
                var o = FromUri(m.Value, warnings);
                if (o != null) result.Add(o);
            }

            var t = text.TrimStart();
            if (t.StartsWith("{") || t.StartsWith("["))
            {
                try
                {
                    var root = new JavaScriptSerializer { MaxJsonLength = MaxInput, RecursionLimit = 64 }.DeserializeObject(t);
                    if (IsEncryptedExport(root)) warnings.Add("Файл экспорта зашифрован паролем. Сделайте в приложении экспорт без шифрования " +
                                                              "(и удалите этот файл сразу после импорта).");
                    else Walk(root, null, result, warnings);
                }
                catch (ArgumentException) { if (result.Count == 0) warnings.Add("Похоже на JSON, но файл не читается."); }
                catch (InvalidOperationException) { if (result.Count == 0) warnings.Add("Файл экспорта слишком большой — разбор прерван."); }
            }

            // Дубли (один и тот же секрет и аккаунт) — один раз.
            var unique = new List<OtpEntry>();
            foreach (var o in result)
                if (!unique.Any(u => u.UseSecret(a => o.UseSecret(b => a == b)) && string.Equals(u.Account ?? "", o.Account ?? "", StringComparison.OrdinalIgnoreCase)))
                    unique.Add(o);
            foreach (var o in unique) o.Id = AppStore.NewId();
            if (unique.Count == 0 && warnings.Count == 0) warnings.Add("Коды 2FA не найдены. Проверьте, что вставлена ссылка или выбран файл экспорта.");
            return unique;
        }

        // ---------- otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=...&digits=...&period=... ----------

        public static OtpEntry FromUri(string uri, List<string> warnings)
        {
            // Avoid System.Uri caching complete secret-bearing query strings.
            // Decode only the label and individual parameters, clearing temporary copies.
            if (uri == null || !uri.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            { warnings.Add("Не разобрана ссылка 2FA."); return null; }
            const string prefix = "otpauth://totp";
            if (!uri.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || uri.Length <= prefix.Length ||
                (uri[prefix.Length] != '/' && uri[prefix.Length] != '?'))
            {
                warnings.Add("Пропущена ссылка: требуется аккаунт TOTP.");
                return null;
            }
            int queryAt = uri.IndexOf('?'), fragmentAt = uri.IndexOf('#');
            if (queryAt < 0 || (fragmentAt >= 0 && fragmentAt < queryAt)) { warnings.Add("В ссылке нет параметров 2FA."); return null; }
            var query = uri.Substring(queryAt + 1, (fragmentAt < 0 ? uri.Length : fragmentAt) - queryAt - 1);
            Dictionary<string,string> q;
            try { q = Query(query); }
            finally { Secure.Wipe(query); }
            string secret;
            if (!q.TryGetValue("secret", out secret) || string.IsNullOrWhiteSpace(secret)) { warnings.Add("В ссылке нет секрета."); return null; }
            string normalized = null;
            try
            {
            int labelAt = prefix.Length + (uri[prefix.Length] == '/' ? 1 : 0);
            var label = Uri.UnescapeDataString(uri.Substring(labelAt, queryAt - labelAt));
            string issuer = q.ContainsKey("issuer") ? q["issuer"] : "", account = label;
            int colon = label.IndexOf(':');
            if (colon >= 0) { if (issuer.Length == 0) issuer = label.Substring(0, colon); account = label.Substring(colon + 1).Trim(); }
            normalized = Totp.Normalize(secret);
            var o = new OtpEntry { Issuer = issuer.Length > 0 ? issuer : account, Account = issuer.Length > 0 ? account : "", Secret = normalized };
            string v; int n;
            if (q.TryGetValue("algorithm", out v)) o.Algorithm = NormAlgo(v);
            if (q.TryGetValue("digits", out v) && int.TryParse(v, out n))
            {
                // Стандартные коды — 6–8 цифр; чужое значение (0/4/999) молча ломало генерацию.
                if (n < 6 || n > 8) { warnings.Add("Нестандартное число цифр (" + n + ") — использую 6"); o.Digits = 6; }
                else o.Digits = n;
            }
            if (q.TryGetValue("period", out v) && int.TryParse(v, out n) && n > 0) o.Period = n;
            return Valid(o, warnings) ? o : null;
            }
            finally { Secure.Wipe(secret); Secure.Wipe(normalized); }
        }

        static Dictionary<string, string> Query(string query)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in query.Split('&'))
            {
                string raw = null, expanded = null;
                try
                {
                int i = part.IndexOf('=');
                if (i <= 0) continue;
                var key = Uri.UnescapeDataString(part.Substring(0, i));
                raw = part.Substring(i + 1); expanded = raw.Replace('+', ' ');
                var decoded = Uri.UnescapeDataString(expanded);
                string old;
                if (key.Equals("secret", StringComparison.OrdinalIgnoreCase) && d.TryGetValue(key, out old)) Secure.Wipe(old);
                d[key] = decoded;
                if (ReferenceEquals(decoded, raw)) raw = null;
                if (ReferenceEquals(decoded, expanded)) expanded = null;
                }
                finally { Secure.Wipe(raw); Secure.Wipe(expanded); Secure.Wipe(part); }
            }
            return d;
        }

        // ---------- Google Authenticator: base64(protobuf MigrationPayload) ----------
        // MigrationPayload { repeated OtpParameters otp_parameters = 1; ... }
        // OtpParameters { bytes secret = 1; string name = 2; string issuer = 3; Algorithm algorithm = 4;
        //                 DigitCount digits = 5; OtpType type = 6; int64 counter = 7; }

        static List<OtpEntry> FromGoogle(string data, List<string> warnings)
        {
            var b64 = Uri.UnescapeDataString(data).Replace('-', '+').Replace('_', '/').Replace(' ', '+');
            while (b64.Length % 4 != 0) b64 += "=";
            var bytes = Convert.FromBase64String(b64);
            var list = new List<OtpEntry>();
            int pos = 0;
            while (pos < bytes.Length)
            {
                ulong key = Varint(bytes, ref pos);
                int field = (int)(key >> 3), wire = (int)(key & 7);
                if (field == 1 && wire == 2)
                {
                    var len = (int)Varint(bytes, ref pos);
                    // Отрицательная/завышенная длина уводила pos назад — вечный цикл с ростом warnings (OOM).
                    if (len < 0 || len > bytes.Length - pos) throw new FormatException("повреждённые данные");
                    var o = OtpParameters(bytes, pos, len, warnings);
                    if (o != null) list.Add(o);
                    pos += len;
                }
                else Skip(bytes, ref pos, wire);
            }
            return list;
        }

        static OtpEntry OtpParameters(byte[] b, int start, int len, List<string> warnings)
        {
            byte[] secret = null; string name = "", issuer = ""; int algo = 1, digits = 1, type = 2;
            int pos = start, end = start + len;
            while (pos < end)
            {
                ulong key = Varint(b, ref pos);
                int field = (int)(key >> 3), wire = (int)(key & 7);
                if (wire == 2)
                {
                    var l = (int)Varint(b, ref pos);
                    // Защита от отрицательной/завышенной длины — иначе pos уходит назад и цикл не заканчивается.
                    if (l < 0 || l > b.Length - pos) throw new FormatException("повреждённые данные");
                    var chunk = new byte[l];
                    Buffer.BlockCopy(b, pos, chunk, 0, l);
                    pos += l;
                    if (field == 1) secret = chunk;
                    else if (field == 2) name = System.Text.Encoding.UTF8.GetString(chunk);
                    else if (field == 3) issuer = System.Text.Encoding.UTF8.GetString(chunk);
                }
                else if (wire == 0)
                {
                    var v = (int)Varint(b, ref pos);
                    if (field == 4) algo = v; else if (field == 5) digits = v; else if (field == 6) type = v;
                }
                else Skip(b, ref pos, wire);
            }
            var label = name;
            int colon = label.IndexOf(':');
            if (colon >= 0) { if (issuer.Length == 0) issuer = label.Substring(0, colon); label = label.Substring(colon + 1).Trim(); }
            if (type == 1) { warnings.Add("Пропущен аккаунт со счётчиком (HOTP): " + (issuer.Length > 0 ? issuer : label)); return null; }
            if (secret == null || secret.Length == 0) { warnings.Add("Пропущен аккаунт без секрета: " + label); return null; }
            var o = new OtpEntry
            {
                Issuer = issuer.Length > 0 ? issuer : label, Account = issuer.Length > 0 ? label : "",
                Secret = Totp.ToBase32(secret),
                Algorithm = algo == 2 ? "SHA256" : algo == 3 ? "SHA512" : "SHA1",
                Digits = digits == 2 ? 8 : 6
            };
            return Valid(o, warnings) ? o : null;
        }

        static ulong Varint(byte[] b, ref int pos)
        {
            ulong r = 0; int shift = 0;
            while (true)
            {
                if (pos >= b.Length) throw new FormatException("данные обрезаны");
                byte x = b[pos++];
                r |= (ulong)(x & 0x7f) << shift;
                if ((x & 0x80) == 0) return r;
                shift += 7;
                if (shift > 63) throw new FormatException("неверные данные");
            }
        }

        static void Skip(byte[] b, ref int pos, int wire)
        {
            switch (wire)
            {
                case 0: Varint(b, ref pos); break;
                case 1: pos += 8; break;
                case 2:
                    {
                        var l = (int)Varint(b, ref pos);
                        // Отрицательная длина двигала pos назад — вечный цикл на крафтовой ссылке.
                        if (l < 0 || l > b.Length - pos) throw new FormatException("повреждённые данные");
                        pos += l;
                        break;
                    }
                case 5: pos += 4; break;
                default: throw new FormatException("неизвестный тип поля " + wire);
            }
        }

        // ---------- JSON-экспорты ----------

        static bool IsEncryptedExport(object root)
        {
            var d = root as Dictionary<string, object>;
            if (d == null) return false;
            object header, db;
            if (d.TryGetValue("header", out header) && header is Dictionary<string, object> && ((Dictionary<string, object>)header).ContainsKey("slots")
                && ((Dictionary<string, object>)header)["slots"] != null && d.TryGetValue("db", out db) && db is string) return true; // Aegis
            object enc;
            if (d.TryGetValue("servicesEncrypted", out enc) && enc is string && ((string)enc).Length > 0) return true; // 2FAS
            return false;
        }

        // Обход любого JSON: объект с полем secret (или info.secret у Aegis, otp.* у 2FAS) — аккаунт;
        // строка otpauth:// в поле totp (Bitwarden) — тоже.
        static void Walk(object node, Dictionary<string, object> parent, List<OtpEntry> result, List<string> warnings)
        {
            var d = node as Dictionary<string, object>;
            if (d != null)
            {
                var info = Get(d, "info") as Dictionary<string, object>;
                var otp = Get(d, "otp") as Dictionary<string, object>;
                var secret = Str(d, "secret") ?? (info != null ? Str(info, "secret") : null);
                if (!string.IsNullOrWhiteSpace(secret))
                {
                    var type = (Str(d, "type") ?? Str(d, "tokenType") ?? (otp != null ? Str(otp, "tokenType") : null) ?? "totp").ToLowerInvariant();
                    var o = new OtpEntry
                    {
                        Issuer = Str(d, "issuer") ?? (otp != null ? Str(otp, "issuer") : null) ?? Str(d, "name") ?? Str(d, "label") ?? "",
                        Account = (otp != null ? Str(otp, "account") : null) ?? Str(d, "account") ?? Str(d, "username") ?? "",
                        Secret = Totp.Normalize(secret)
                    };
                    // У Aegis/andOTP name/label — это аккаунт, если есть issuer.
                    if (o.Account.Length == 0 && Str(d, "issuer") != null) o.Account = Str(d, "name") ?? Str(d, "label") ?? "";
                    var src = info ?? otp ?? d;
                    var algo = Str(src, "algo") ?? Str(src, "algorithm");
                    if (algo != null) o.Algorithm = NormAlgo(algo);
                    int n;
                    if (int.TryParse(Str(src, "digits") ?? "", out n)) o.Digits = n;
                    if (int.TryParse(Str(src, "period") ?? "", out n) && n > 0) o.Period = n;
                    int tn;
                    // Aegis пишет type числом: 1=TOTP, 2=HOTP, 3=Steam. Числовой тип раньше проходил
                    // проверки Contains("hotp") и молча валидировался как TOTP — коды получались неверными.
                    if (int.TryParse(type, out tn) && tn != 1) { warnings.Add("Пропущен аккаунт типа HOTP/Steam (поддерживается только TOTP): " + o.Issuer); return; }
                    if (type.Contains("hotp")) warnings.Add("Пропущен аккаунт со счётчиком (HOTP): " + o.Issuer);
                    else if (type.Contains("steam")) warnings.Add("Пропущен код Steam Guard (особый формат): " + o.Issuer);
                    else if (Valid(o, warnings)) result.Add(o);
                    return;
                }
                var totp = Str(d, "totp");
                if (!string.IsNullOrWhiteSpace(totp) && parent != null)
                {
                    if (totp.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)) { var o = FromUri(totp, warnings); if (o != null) result.Add(o); }
                    else
                    {
                        var o = new OtpEntry { Issuer = Str(parent, "name") ?? "", Account = Str(d, "username") ?? "", Secret = Totp.Normalize(totp) };
                        if (Valid(o, warnings)) result.Add(o);
                    }
                    return;
                }
                foreach (var kv in d) Walk(kv.Value, d, result, warnings);
                return;
            }
            var arr = node as IEnumerable;
            if (arr != null && !(node is string))
                foreach (var x in arr) Walk(x, parent, result, warnings);
        }

        static object Get(Dictionary<string, object> d, string key)
        {
            foreach (var kv in d) if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase)) return kv.Value;
            return null;
        }

        static string Str(Dictionary<string, object> d, string key)
        {
            var v = Get(d, key);
            if (v == null) return null;
            var s = Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture);
            return string.IsNullOrWhiteSpace(s) ? null : s.Trim();
        }

        static string NormAlgo(string a)
        {
            a = (a ?? "").ToUpperInvariant().Replace("-", "");
            return a == "SHA256" || a == "SHA512" ? a : "SHA1";
        }

        static bool Valid(OtpEntry o, List<string> warnings)
        {
            try { o.UseSecret(s => Totp.Code(s, o.Algorithm, o.Digits, o.Period, 0)); return true; }
            catch (FormatException) { warnings.Add("Неверный секрет у аккаунта: " + o.Issuer); return false; }
        }

        // Ссылка в предупреждении — без секрета: окно импорта видно на экране (и на скриншотах).
        static string Short(string s)
        {
            s = Regex.Replace(s, @"(?i)(secret=)[^&\s]*", "$1•••");
            return s.Length > 60 ? s.Substring(0, 60) + "..." : s;
        }

        public static string ReadFile(string path)
        {
            byte[] bytes = SafeStorage.ReadBounded(path, MaxInput);
            try
            {
                using (var stream = new MemoryStream(bytes, false))
                using (var reader = new StreamReader(stream, System.Text.Encoding.UTF8, true)) return reader.ReadToEnd();
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace WinUp
{
    // Official portable archive: SHA-256 from keepass.info, then Authenticode
    // verification of its KeePass.exe. Verified bytes become the external core.
    public static class CoreUpdate
    {
        public const string HomeUrl = "https://keepass.info/";
        public const string IntegrityUrl = "https://keepass.info/integrity.html";
        // Прямая ссылка официальной страницы загрузки (SourceForge, /download редиректит на зеркало).
        public const string ZipUrlPattern = "https://sourceforge.net/projects/keepass/files/KeePass%202.x/{0}/KeePass-{0}.zip/download";

        static CoreUpdate()
        {
            // Сборка без атрибута целевой платформы (csc из «Собрать.cmd») работает в режиме совместимости
            // с .NET 4.0 и предлагает только SSL3/TLS 1.0 — keepass.info и sourceforge такие соединения
            // отклоняют («Не удалось создать защищенный канал SSL/TLS»). TLS 1.2 включаем явно.
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch { }
        }

        // Пользователь согласился перезапустить WinUp после подготовки обновления.
        public static bool RestartPendingFlag;

        // ---------------- Парсинг (открыт для тестов) ----------------

        // Главная keepass.info, блок Latest News: "<b>KeePass 2.61.1 released</b>".
        public static string ParseLatestVersion(string html)
        {
            if (html == null) return null;
            var m = Regex.Match(html, @"KeePass\s+(2\.\d+(?:\.\d+)?)\s+released", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : null;
        }

        // Страница целостности — HTML-таблица: "<b>KeePass-2.61.1-Source.zip</b>:" и ниже
        // "<td>SHA-256:</td><td><code>XXXXXXXX XXXXXXXX ...</code>" (8 групп по 8). Теги убираем,
        // дальше разбор как по тексту. fileName — имя архива, например "KeePass-2.61.1-Source.zip".
        public static string ParseZipSha256(string html, string fileName)
        {
            if (html == null) return null;
            var text = WebUtility.HtmlDecode(Regex.Replace(html, "<[^>]+>", " "));
            var block = Regex.Match(text, Regex.Escape(fileName) + @"\s*:(.*?)(?=KeePass-\d[^\s:]*\s*:|\z)", RegexOptions.Singleline);
            if (!block.Success) return null;
            var h = Regex.Match(block.Groups[1].Value, @"SHA-256:((?:\s*[0-9A-Fa-f]{8}){8})");
            if (!h.Success) return null;
            return Regex.Replace(h.Groups[1].Value, @"\s", "").ToUpperInvariant();
        }

        public static string SourceZipName(string version) { return "KeePass-" + version + "-Source.zip"; }

        public static bool IsNewer(string have, string latest)
        {
            var a = ParseVer(have);
            var b = ParseVer(latest);
            if (b == null) return false;
            if (a == null) return true; // своя версия неизвестна (ядро не загрузилось) — обновление нужно
            for (int i = 0; i < 3; i++)
                if (a[i] != b[i]) return b[i] > a[i];
            return false;
        }

        static int[] ParseVer(string v)
        {
            if (string.IsNullOrEmpty(v)) return null;
            var p = v.Split('.');
            if (p.Length < 2) return null;
            var r = new int[3];
            for (int i = 0; i < 3; i++)
            {
                int n;
                r[i] = i < p.Length && int.TryParse(p[i], out n) ? n : 0;
            }
            return r;
        }

        // ---------------- Сеть ----------------

        static HttpWebRequest NewReq(string url)
        {
            var rq = (HttpWebRequest)WebRequest.Create(url);
            rq.Timeout = 15000;
            rq.ReadWriteTimeout = 30000;
            rq.UserAgent = "WinUp (keepasslib core updater)";
            return rq;
        }

        // Человекочитаемая ошибка сети: 407 (корпоративный прокси без авторизации),
        // таймаут и прочее — со ссылкой на ручной путь обновления.
        static string NetError(Exception ex)
        {
            string reason;
            var w = ex as WebException;
            if (w != null && w.Response is HttpWebResponse)
                reason = "сервер вернул код " + (int)((HttpWebResponse)w.Response).StatusCode;
            else if (w != null && w.Status == WebExceptionStatus.Timeout)
                reason = "время ожидания истекло";
            else reason = ex.Message;
            return "Нет доступа к серверу обновлений (" + reason + ").\n" +
                   "Проверьте интернет-соединение или обновите крипто-ядро вручную\n" +
                   "(Инструкция.html, раздел «Обновление безопасности»).";
        }

        public static string FetchText(string url, out string error)
        {
            error = null;
            try
            {
                using (var resp = NewReq(url).GetResponse())
                using (var s = resp.GetResponseStream())
                using (var r = new StreamReader(s, Encoding.UTF8))
                    return r.ReadToEnd();
            }
            catch (Exception ex) { error = NetError(ex); return null; }
        }

        // Архив — в память (не больше MaxZipBytes): проверенные байты и распакованные — одни и те же.
        public const int MaxZipBytes = 64 * 1024 * 1024;

        public static byte[] DownloadBytes(string url, int maxBytes, out string error)
        { return DownloadBytes(url, maxBytes, true, out error); }

        static byte[] DownloadBytes(string url, int maxBytes, bool allowRefresh, out string error)
        {
            error = null;
            try
            {
                var rq = NewReq(url);
                rq.AllowAutoRedirect = true; // /download → зеркало sourceforge
                using (var resp = rq.GetResponse())
                using (var s = resp.GetResponseStream())
                using (var m = new MemoryStream())
                {
                    var buf = new byte[65536];
                    int n;
                    while ((n = s.Read(buf, 0, buf.Length)) > 0)
                    {
                        m.Write(buf, 0, n);
                        if (m.Length > maxBytes)
                        {
                            error = "Архив обновления больше " + (maxBytes / 1048576) + " МБ.";
                            return null;
                        }
                    }
                    var result = m.ToArray();
                    if (allowRefresh && result.Length < 1024 * 1024 && (resp.ContentType ?? "").IndexOf("text/html", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        var from = new Uri(url);
                        if (from.Scheme == "https" && (from.Host == "sourceforge.net" || from.Host.EndsWith(".sourceforge.net", StringComparison.OrdinalIgnoreCase)))
                        {
                            var match = Regex.Match(Encoding.UTF8.GetString(result), @"<meta\b[^>]*\bcontent\s*=\s*[""']\s*\d+\s*;\s*url=(?<url>[^""']+)", RegexOptions.IgnoreCase);
                            Uri next;
                            if (match.Success && Uri.TryCreate(WebUtility.HtmlDecode(match.Groups["url"].Value), UriKind.Absolute, out next) && next.Scheme == "https" && next.Host.EndsWith(".sourceforge.net", StringComparison.OrdinalIgnoreCase))
                                return DownloadBytes(next.AbsoluteUri, maxBytes, false, out error);
                        }
                    }
                    return result;
                }
            }
            catch (Exception ex) { error = NetError(ex); return null; }
        }

        // ---------------- Сценарии ----------------

        // Версия последнего релиза KeePass с официального сайта или null (error — по-русски).
        public static string CheckLatest(out string error) { return CheckLatest(HomeUrl, out error); }

        public static string CheckLatest(string homeUrl, out string error)
        {
            string html = FetchText(homeUrl, out error);
            if (html == null) return null;
            string latest = ParseLatestVersion(html);
            if (latest == null)
                error = "Не удалось разобрать страницу keepass.info:\nновость о выпуске KeePass не найдена.";
            return latest;
        }

        // Hash + publisher signature; installation is atomic and applies on restart.
        public static bool DownloadAndStage(string version, Action<string> log, out string error)
        {
            return DownloadAndStage(version, IntegrityUrl, string.Format(ZipUrlPattern, version), log, out error);
        }

        public static bool DownloadAndStage(string version, string integrityUrl, string zipUrl, Action<string> log, out string error)
        {
            error = null;
            if (!Regex.IsMatch(version ?? "", @"^2\.\d+(?:\.\d+)?$")) { error = "Неверная версия KeePass."; return false; }
            string package = "KeePass-" + version + ".zip";
            string html = FetchText(integrityUrl, out error);
            if (html == null) return false;
            string expected = ParseZipSha256(html, package);
            if (expected == null) { error = "На keepass.info не найдена контрольная сумма " + package + "."; return false; }
            if (log != null) log("Скачиваю официальный подписанный пакет KeePass " + version + "...");
            byte[] zip = DownloadBytes(zipUrl, MaxZipBytes, out error);
            if (zip == null) return false;
            if (!string.Equals(CoreLoader.Sha256(zip), expected, StringComparison.OrdinalIgnoreCase))
            { error = "Контрольная сумма пакета не совпала с официальной. Обновление отменено."; return false; }
            if (!StageSignedPackage(zip, version, out error)) return false;
            if (log != null) log("Подпись издателя KeePass проверена. Обновление применится при следующем запуске.");
            return true;
        }

        public static bool StageSignedPackage(byte[] zipBytes, string version, out string error)
        {
            error = null;
            string stage = null;
            try
            {
                if (zipBytes == null || zipBytes.Length > MaxZipBytes) throw new InvalidDataException("Неверный пакет обновления.");
                stage = NewPrivateDir();
                var candidate = Path.Combine(stage, "KeePass.exe");
                using (var archive = new ZipArchive(new MemoryStream(zipBytes, false), ZipArchiveMode.Read))
                {
                    var entry = archive.GetEntry("KeePass.exe");
                    if (entry == null || entry.Length <= 0 || entry.Length > 32 * 1024 * 1024)
                        throw new InvalidDataException("В пакете нет подписанного ядра KeePass.");
                    using (var input = entry.Open())
                    using (var output = File.Create(candidate))
                    {
                        var buffer = new byte[65536];
                        int count;
                        while ((count = input.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            if (output.Length + count > 32 * 1024 * 1024) throw new InvalidDataException("Ядро слишком велико.");
                            output.Write(buffer, 0, count);
                        }
                    }
                }
                Version actual;
                byte[] dll = CoreLoader.ReadVerifiedCore(candidate, out actual);
                var requested = new Version(version);
                if (actual.Major != requested.Major || actual.Minor != requested.Minor || actual.Build != Math.Max(0, requested.Build))
                    throw new InvalidDataException("Версия подписанного ядра не совпадает с ожидаемой.");
                Directory.CreateDirectory(CoreLoader.CoreDir);
                string target = CoreLoader.CoreFile;
                if (File.Exists(target)) File.Copy(target, target + ".old", true);
                Paths.AtomicWrite(target, dll);
                return true;
            }
            catch (Exception ex) { error = "Обновление отменено: " + ex.Message; return false; }
            finally { if (stage != null) try { Directory.Delete(stage, true); } catch { } }
        }
        // Личная папка сборки: %TEMP%\WinUp-core-<случайное>, доступ только у текущего пользователя
        // (права родителя не наследуются). Всегда новая: заготовка с тем же именем не используется.
        internal static string NewPrivateDir()
        {
            var dir = Path.Combine(Path.GetTempPath(), "WinUp-core-" + Guid.NewGuid().ToString("N").Substring(0, 12));
            if (Directory.Exists(dir)) throw new IOException("Папка сборки уже существует: " + dir);
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(true, false);
            sec.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(dir, sec);
            return dir;
        }


    }
}

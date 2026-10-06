using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp
{
    // Интеграция с браузером: значок в полях входа на сайтах, вставка логина/пароля/кода 2FA.
    // Архитектура: расширение (Chrome/Edge/Яндекс, распакованное) --Native Messaging--> WinUp.exe
    // в режиме моста (Program.Main) --> именованный канал --> работающее окно WinUp (BrowserServer).
    // Сопряжение: расширение генерирует токен, WinUp показывает код из токена, пользователь сверяет.

    // Хост записи сайта: регистрируемый домен для сравнения «тот же сайт».
    static class SiteDomain
    {
        // Двухуровневые суффиксы, где сайт живёт на третьем уровне (esia.gosuslugi.ru → gosuslugi.ru,
        // но gosuslugi.ru.evil.com → evil.com).
        static readonly HashSet<string> Suffixes = new HashSet<string>
        {
            "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru",
            "com.ua", "co.uk", "org.uk", "com.au", "co.jp", "com.br", "com.tr", "com.kz",
            "github.io", "gitlab.io", "vercel.app", "netlify.app", "herokuapp.com", "web.app",
            "firebaseapp.com", "pages.dev", "blogspot.com", "narod.ru", "ucoz.ru"
        };

        // Хост из адреса записи (без схемы → https://) или страницы. null для мусора.
        public static string HostOf(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return null;
            var u = url.Trim();
            if (!Uri.CheckSchemeName(SchemeOf(u))) { /* не мешает: Uri сам разберётся ниже */ }
            Uri uri;
            if (!Uri.TryCreate(u, UriKind.Absolute, out uri))
            {
                if (!Uri.TryCreate("https://" + u, UriKind.Absolute, out uri)) return null;
            }
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return null;
            var host = uri.Host;
            if (string.IsNullOrEmpty(host)) return null;
            return host.ToLowerInvariant();
        }

        static string SchemeOf(string u)
        {
            var i = u.IndexOf(':');
            return i > 0 ? u.Substring(0, i) : "";
        }

        public static bool IsHttpUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return false;
            return url.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase);
        }

        static bool IsIp(string host)
        {
            if (host.IndexOf(':') >= 0) return true; // IPv6
            var parts = host.Split('.');
            if (parts.Length != 4) return false;
            foreach (var p in parts)
            {
                int n;
                if (p.Length == 0 || p.Length > 3 || !int.TryParse(p, out n) || n < 0 || n > 255) return false;
                if (p.Length > 1 && p[0] == '0') return false;
            }
            return true;
        }

        // Регистрируемый домен хоста. IP, localhost и односегментные имена сравниваются целиком.
        public static string Registrable(string host)
        {
            if (string.IsNullOrEmpty(host)) return null;
            if (IsIp(host)) return host;
            if (host == "localhost" || host.EndsWith(".localhost")) return host;
            var labels = host.Split('.');
            if (labels.Length <= 2) return host;
            if (Suffixes.Contains(labels[labels.Length - 2] + "." + labels[labels.Length - 1]))
                return labels[labels.Length - 3] + "." + labels[labels.Length - 2] + "." + labels[labels.Length - 1];
            return labels[labels.Length - 2] + "." + labels[labels.Length - 1];
        }

        // Точно тот же адрес (без учёта «www.»): вставка без вопроса допускается только здесь.
        public static bool SameHost(string hostA, string hostB)
        {
            if (string.IsNullOrEmpty(hostA) || string.IsNullOrEmpty(hostB)) return false;
            Func<string, string> strip = h => h.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? h.Substring(4) : h;
            return string.Equals(strip(hostA), strip(hostB), StringComparison.OrdinalIgnoreCase);
        }

        // Один ли это сайт (по регистрируемому домену; IP и localhost — только точное совпадение).
        public static bool SameSite(string hostA, string hostB)
        {
            if (string.IsNullOrEmpty(hostA) || string.IsNullOrEmpty(hostB)) return false;
            if (IsIp(hostA) || IsIp(hostB) || hostA == "localhost" || hostB == "localhost" ||
                hostA.EndsWith(".localhost") || hostB.EndsWith(".localhost"))
                return string.Equals(hostA, hostB, StringComparison.OrdinalIgnoreCase);
            return string.Equals(Registrable(hostA), Registrable(hostB), StringComparison.OrdinalIgnoreCase);
        }
    }

    // Сопряжение расширений: HKCU\Software\WinUp\Browser\Paired, имя значения = SHA-256(токен),
    // данные = «Браузер|дата». Токен знает только расширение (chrome.storage.local) и мост.
    static class BrowserPair
    {
        const string KeyRoot = @"Software\WinUp\Browser";
        const string PairedSub = "Paired";

        public static string HashToken(string token)
        {
            using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(token ?? ""))).Replace("-", "").ToLowerInvariant();
        }

        // Код сопряжения: первые 4 байта SHA-256(токен) как big-endian uint32, % 1 000 000, до 6 цифр.
        // Так же считает background.js — код в расширении и в окне WinUp совпадает.
        public static string CodeOf(string token)
        {
            byte[] h;
            using (var sha = SHA256.Create()) h = sha.ComputeHash(Encoding.UTF8.GetBytes(token ?? ""));
            uint n = ((uint)h[0] << 24) | ((uint)h[1] << 16) | ((uint)h[2] << 8) | h[3];
            return (n % 1000000).ToString("D6");
        }

        public static bool IsPaired(string token)
        {
            if (string.IsNullOrEmpty(token)) return false;
            using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(KeyRoot + "\\" + PairedSub))
                return k != null && k.GetValue(HashToken(token)) != null;
        }

        public static void Save(string token, string browser)
        {
            using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(KeyRoot + "\\" + PairedSub))
                k.SetValue(HashToken(token), (browser ?? "?") + "|" + DateTime.Now.ToString("dd.MM.yyyy HH:mm"));
        }

        public static void Forget(string tokenHash)
        {
            using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(KeyRoot + "\\" + PairedSub, true))
                if (k != null) k.DeleteValue(tokenHash, false);
        }

        // Хэш токена → «Браузер|дата».
        public static Dictionary<string, string> List()
        {
            var r = new Dictionary<string, string>();
            using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(KeyRoot + "\\" + PairedSub))
            {
                if (k == null) return r;
                foreach (var name in k.GetValueNames())
                {
                    var v = k.GetValue(name) as string;
                    if (!string.IsNullOrEmpty(v)) r[name] = v;
                }
            }
            return r;
        }
    }

    // Именованный канал мост→окно: имя зависит от папки, как мьютекс одного экземпляра.
    static class BrowserPipe
    {
        public const int MaxRequestBytes = 64 * 1024;
        public static string Name { get { return "WinUp-browser-" + Program.FolderHash(Paths.Root); } }
    }

    // Режим моста Native Messaging: браузер запускает WinUp.exe "chrome-extension://<id>/",
    // тот пересылает одно сообщение в окно WinUp и возвращает один ответ.
    static class BrowserBridge
    {
        public const string AllowedOrigin = "chrome-extension://dmbmnobicgmfcbaapndecbngkgdemefh/";

        public static void Run(string origin)
        {
            try
            {
                if (!string.Equals(origin, AllowedOrigin, StringComparison.OrdinalIgnoreCase))
                {
                    WriteOut("{\"ok\":false,\"error\":\"bad_origin\"}");
                    return;
                }
                string msg = ReadFrame();
                if (string.IsNullOrEmpty(msg)) return;

                var js = new JavaScriptSerializer { MaxJsonLength = BrowserPipe.MaxRequestBytes };
                Dictionary<string, object> d;
                try { d = js.Deserialize<Dictionary<string, object>>(msg); }
                catch { WriteOut("{\"ok\":false,\"error\":\"bad_request\"}"); return; }
                object t;
                string type = d != null && d.TryGetValue("type", out t) ? t as string : null;

                // Запуск WinUp мост обрабатывает сам: окно не обязано быть открыто.
                if (type == "launch")
                {
                    try
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                            Application.ExecutablePath));
                        WriteOut("{\"ok\":true}");
                    }
                    catch { WriteOut("{\"ok\":false,\"error\":\"launch_failed\"}"); }
                    return;
                }

                try
                {
                    using (var pipe = new NamedPipeClientStream(".", BrowserPipe.Name, PipeDirection.InOut))
                    {
                        // Connect бросает исключение, если канал не появился за таймаут, —
                        // значит окно WinUp не работает.
                        bool up = false;
                        try { pipe.Connect(1500); up = true; }
                        catch { }
                        if (!up) { WriteOut("{\"ok\":false,\"error\":\"not_running\"}"); return; }
                        // Канал с тем же именем могла создать другая программа (раньше, чем запустился WinUp):
                        // запрос с токеном сопряжения уходит только окну этого же WinUp.exe.
                        if (BrowserCaller.CheckServer(pipe) != null) { WriteOut("{\"ok\":false,\"error\":\"bad_server\"}"); return; }
                        using (var w = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true })
                        using (var r = new StreamReader(pipe, Encoding.UTF8))
                        {
                            w.Write(msg + "\n");
                            do
                            {
                                string resp = r.ReadLine();
                                WriteOut(string.IsNullOrEmpty(resp) ? "{\"ok\":false,\"error\":\"not_running\"}" : resp);
                                if (string.IsNullOrEmpty(resp) || type != "watch") break;
                            } while (true);
                        }
                    }
                }
                catch { WriteOut("{\"ok\":false,\"error\":\"not_running\"}"); }
            }
            catch { try { WriteOut("{\"ok\":false,\"error\":\"host_error\"}"); } catch { } }
        }

        // Кадр Native Messaging: 4 байта длины (little-endian) + UTF-8 JSON.
        static string ReadFrame()
        {
            var s = Console.OpenStandardInput();
            var len = new byte[4];
            if (!ReadFull(s, len, 4)) return null;
            int n = len[0] | (len[1] << 8) | (len[2] << 16) | (len[3] << 24);
            if (n <= 0 || n > BrowserPipe.MaxRequestBytes) return null;
            var buf = new byte[n];
            if (!ReadFull(s, buf, n)) return null;
            return Encoding.UTF8.GetString(buf);
        }

        static bool ReadFull(Stream s, byte[] buf, int count)
        {
            int done = 0;
            while (done < count)
            {
                int n = s.Read(buf, done, count - done);
                if (n <= 0) return false;
                done += n;
            }
            return true;
        }

        static void WriteOut(string json)
        {
            var payload = Encoding.UTF8.GetBytes(json);
            try
            {
            int n = payload.Length;
            var len = new byte[] { (byte)(n & 255), (byte)((n >> 8) & 255), (byte)((n >> 16) & 255), (byte)((n >> 24) & 255) };
            var o = Console.OpenStandardOutput();
            o.Write(len, 0, 4);
            o.Write(payload, 0, payload.Length);
            o.Flush();
            }
            finally { Array.Clear(payload, 0, payload.Length); Secure.Wipe(json); }
        }
    }

    // Подключение расширения: файлы в %LOCALAPPDATA%\WinUp\browser, манифест моста и ключи реестра
    // Native Messaging в HKCU для известных Chromium-браузеров. Папка НЕ рядом с exe:
    // у флешки меняется буква, и браузер теряет расширение.
    static class BrowserSetup
    {
        public const string HostName = "ru.winup.browser";
        public const string ExtensionId = "dmbmnobicgmfcbaapndecbngkgdemefh";

        static string RootDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinUp"); } }
        public static string BrowserDir { get { return Path.Combine(RootDir, "browser"); } }
        public static string HostManifestPath { get { return Path.Combine(RootDir, HostName + ".json"); } }

        // Браузеры, в чьи ключи Native Messaging пишем путь манифеста моста.
        static readonly string[] RegBrowsers =
        {
            @"Software\Google\Chrome\NativeMessagingHosts",
            @"Software\Microsoft\Edge\NativeMessagingHosts",
            @"Software\Chromium\NativeMessagingHosts",
            @"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
            @"Software\Yandex\YandexBrowser\NativeMessagingHosts"
        };

        public static bool Enabled
        {
            get
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\WinUp\Browser"))
                    return k != null && Convert.ToString(k.GetValue("Enabled")) == "1";
            }
        }

        // Распаковка вшитых файлов расширения. true, если что-то обновили.
        static bool ExtractExtension()
        {
            bool changed = false;
            var asm = Assembly.GetExecutingAssembly();
            var names = asm.GetManifestResourceNames().Where(x => x.StartsWith("browser/", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (names.Length == 0) return false;
            Directory.CreateDirectory(BrowserDir);
            foreach (var name in names)
            {
                var file = name.Substring("browser/".Length);
                if (file.Length == 0 || file.IndexOf('/') >= 0) continue; // плоская папка
                var dst = Path.Combine(BrowserDir, file);
                using (var s = ComponentResources.Open(name))
                {
                    if (s == null) continue;
                    var data = new byte[s.Length];
                    s.Read(data, 0, data.Length);
                    if (!File.Exists(dst) || !File.ReadAllBytes(dst).SequenceEqual(data))
                    {
                        File.WriteAllBytes(dst, data);
                        changed = true;
                    }
                }
            }
            return changed;
        }

        static string EmbeddedManifestVersion()
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var s = ComponentResources.Open("browser/manifest.json"))
            {
                if (s == null) return null;
                var data = new byte[s.Length];
                s.Read(data, 0, data.Length);
                var js = new JavaScriptSerializer();
                Dictionary<string, object> m;
                try { m = js.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(data)); }
                catch { return null; }
                object v;
                return m != null && m.TryGetValue("version", out v) ? Convert.ToString(v) : null;
            }
        }

        static string DiskManifestVersion()
        {
            try
            {
                var p = Path.Combine(BrowserDir, "manifest.json");
                if (!File.Exists(p)) return null;
                var js = new JavaScriptSerializer();
                Dictionary<string, object> m;
                try { m = js.Deserialize<Dictionary<string, object>>(File.ReadAllText(p, Encoding.UTF8)); }
                catch { return null; }
                object v;
                return m != null && m.TryGetValue("version", out v) ? Convert.ToString(v) : null;
            }
            catch { return null; }
        }

        static void WriteHostManifest()
        {
            var manifest = "{\n" +
                "  \"name\": \"" + HostName + "\",\n" +
                "  \"description\": \"Мост WinUp: расширение браузера вставляет пароли из WinUp\",\n" +
                "  \"path\": " + JsonQuote(Application.ExecutablePath) + ",\n" +
                "  \"type\": \"stdio\",\n" +
                "  \"allowed_origins\": [\"chrome-extension://" + ExtensionId + "/\"]\n" +
                "}";
            Directory.CreateDirectory(RootDir);
            File.WriteAllText(HostManifestPath, manifest, new UTF8Encoding(false));
        }

        static string JsonQuote(string s)
        {
            var js = new JavaScriptSerializer();
            return js.Serialize(s);
        }

        // Подключить: файлы расширения, манифест моста, ключи браузеров, флаг.
        public static void Connect()
        {
            ExtractExtension();
            WriteHostManifest();
            foreach (var b in RegBrowsers)
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(b + "\\" + HostName))
                    k.SetValue(null, HostManifestPath);
            }
            using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\WinUp\Browser"))
                k.SetValue("Enabled", "1", Microsoft.Win32.RegistryValueKind.String);
        }

        // Отключить: ключи моста, флаг, файлы расширения и манифеста. Сопряжения (Paired) не трогаем —
        // для них в диалоге своя кнопка «Забыть».
        public static void Disconnect()
        {
            foreach (var b in RegBrowsers)
            {
                try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(b + "\\" + HostName, false); }
                catch { }
            }
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\WinUp\Browser", true))
                    if (k != null) k.DeleteValue("Enabled", false);
            }
            catch { }
            try { File.Delete(HostManifestPath); }
            catch { }
            try { Directory.Delete(BrowserDir, true); }
            catch { }
        }

        // При каждом запуске WinUp с включённым расширением: путь к exe в манифесте моста мог
        // измениться (перенос папки), а файлы расширения сверяются со вшитыми побайтно. Сверки
        // только по версии мало: изменённый content.js с прежним номером версии остался бы
        // (браузер не проверяет файлы распакованного расширения), а сопряжение у него уже есть.
        public static void RefreshIfNeeded()
        {
            try
            {
                if (!Enabled) return;
                WriteHostManifest(); // актуальный путь exe
                // Другая версия на диске — это обновление WinUp, а не подмена: файлы заменяются без тревоги.
                var before = DiskManifestVersion();
                var embedded = EmbeddedManifestVersion();
                RestoredFiles = RemoveForeignFiles() + (ExtractExtension() ? 1 : 0);
                if (RestoredFiles > 0 && before != null && embedded != null && before != embedded)
                {
                    UpdatedFrom = before;
                    RestoredFiles = 0;
                }
            }
            catch { }
        }

        // Сколько файлов восстановлено/убрано при последней сверке (для журнала).
        public static int RestoredFiles;
        // Версия расширения, с которой файлы обновлены при этом запуске (null — не обновлялись).
        public static string UpdatedFrom;
        public static string Version { get { return EmbeddedManifestVersion(); } }

        // Лишние файлы в папке расширения (не из вшитого набора) — удаляются: браузер загрузил бы и их.
        static int RemoveForeignFiles()
        {
            if (!Directory.Exists(BrowserDir)) return 0;
            var known = new HashSet<string>(Assembly.GetExecutingAssembly().GetManifestResourceNames()
                .Where(x => x.StartsWith("browser/", StringComparison.OrdinalIgnoreCase))
                .Select(x => x.Substring("browser/".Length)), StringComparer.OrdinalIgnoreCase);
            int n = 0;
            foreach (var f in Directory.GetFiles(BrowserDir, "*", SearchOption.AllDirectories))
            {
                var rel = f.Substring(BrowserDir.Length).TrimStart('\\');
                if (known.Contains(rel)) continue;
                try { File.Delete(f); n++; } catch { }
            }
            foreach (var d in Directory.GetDirectories(BrowserDir))
                try { Directory.Delete(d, true); n++; } catch { }
            return n;
        }
    }

    // Сервер именованного канала: принимает запросы моста, ответы готовит по протоколу расширения.
    // База и диалоги доступны только через Invoke в поток интерфейса.
    class BrowserServer
    {
        MainForm owner;
        volatile bool stop;
        Thread accept;
        readonly SemaphoreSlim connections = new SemaphoreSlim(16);

        public void Start(MainForm form)
        {
            owner = form;
            stop = false;
            accept = new Thread(AcceptLoop);
            accept.IsBackground = true;
            accept.Start();
        }

        public void Stop()
        {
            stop = true;
            try
            {
                using (var c = new NamedPipeClientStream(".", BrowserPipe.Name, PipeDirection.Out))
                    c.Connect(300);
            }
            catch { }
        }

        void AcceptLoop()
        {
            // CreateNewInstance: следующий экземпляр канала создаётся, пока предыдущий ещё обслуживает запрос
            // (открыт вопрос «Вставить?» или сопряжение). Без этого права второй запрос в это время получал
            // «WinUp не запущен». Чужой экземпляр с тем же именем мост отвергает сам (BrowserCaller.CheckServer).
            var sec = new PipeSecurity();
            sec.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,
                PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
            WarnIfSquatted();
            while (!stop)
            {
                NamedPipeServerStream pipe = null;
                try
                {
                    pipe = new NamedPipeServerStream(BrowserPipe.Name, PipeDirection.InOut, 100,
                        PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, sec);
                    pipe.WaitForConnection();
                    if (stop) { pipe.Dispose(); break; }
                }
                catch
                {
                    if (pipe != null) try { pipe.Dispose(); } catch { }
                    if (stop) break;
                    Thread.Sleep(500);
                    continue;
                }
                var p = pipe;
                if (!connections.Wait(0)) { p.Dispose(); continue; }
                var t = new Thread(delegate()
                {
                    try { Serve(p); } catch { }
                    finally { try { p.Dispose(); } catch { } connections.Release(); }
                });
                t.IsBackground = true;
                t.Start();
            }
        }

        // Лимиты: поиск и списки — не чаще 90 в минуту на браузер; больше 5 выданных паролей за минуту —
        // каждый следующий только после подтверждения в окне WinUp. Сопряжение после отказа — пауза 30 с.
        public const int LookupsPerMinute = 90, FillsWithoutQuestion = 5, PairCooldownSeconds = 30;
        readonly RateWindow lookups = new RateWindow(TimeSpan.FromMinutes(1));
        readonly RateWindow fills = new RateWindow(TimeSpan.FromMinutes(1));
        DateTime pairDeniedAt = DateTime.MinValue, lastUnlock = DateTime.MinValue, lastRejectLog = DateTime.MinValue;
        // Открыт диалог WinUp по запросу расширения (сопряжение или «Вставить?») — следующие такие запросы
        // получают «занято», а не стопку окон друг на друге. Читается и пишется только в потоке интерфейса.
        bool askOpen;
        readonly HashSet<string> watchers = new HashSet<string>();
        readonly Dictionary<string, DateTime> cancelledPasskeys = new Dictionary<string, DateTime>();
        readonly Dictionary<string, DateTime> usedPasskeyRequests = new Dictionary<string, DateTime>();

        // Канал с именем WinUp уже есть до запуска окна — его создала другая программа (второй WinUp из этой
        // папки не запускается). Расширение с ней работать не будет (мост её отвергнет); сообщаем пользователю.
        void WarnIfSquatted()
        {
            try
            {
                using (var c = new NamedPipeClientStream(".", BrowserPipe.Name, PipeDirection.InOut))
                {
                    c.Connect(100);
                    var who = Proc.ImagePath(Proc.ServerPid(c));
                    if (who != null && Proc.SameFile(who, Application.ExecutablePath)) return;
                    // Сервер стартует из конструктора окна: журнал примет запись, когда у окна появится хэндл.
                    for (int i = 0; i < 100 && !owner.IsHandleCreated; i++) Thread.Sleep(100);
                    owner.PwLogAsync("Расширение: канал связи с браузером уже занят другой программой" +
                        (who != null ? " (" + who + ")" : "") + ". Расширение не получит ответов, пока она работает. " +
                        "Если вы её не знаете, проверьте ПК антивирусом.");
                }
            }
            catch { } // канала нет — обычный случай
        }

        // Одна строка JSON на запрос, одна строка на ответ.
        void Serve(NamedPipeServerStream pipe)
        {
            try
            {
                // Отвечаем только мосту — этому же WinUp.exe, запущенному браузером (BrowserCaller).
                string browserExe;
                string why = BrowserCaller.Check(Proc.ClientPid(pipe), out browserExe);
                string resp;
                if (why != null)
                {
                    // Reject before reading: an attacker must not hold a worker by sending no newline.
                    resp = Err("bad_caller");
                    lock (connections)
                    {
                        // В журнал — не чаще раза в 30 с: поток отказов не должен вытеснять остальные записи.
                        if (DateTime.UtcNow - lastRejectLog > TimeSpan.FromSeconds(30))
                        {
                            lastRejectLog = DateTime.UtcNow;
                            owner.PwLogAsync("Расширение: запрос отклонён — " + why + ".");
                        }
                    }
                }
                else
                {
                    var line = ReadRequest(pipe);
                    if (stop || string.IsNullOrEmpty(line)) return;
                    if (WatchRequest(pipe, line)) return;
                    resp = Dispatch(line);
                }
                byte[] buf = null;
                try
                {
                    var size = Encoding.UTF8.GetByteCount(resp);
                    buf = new byte[size + 1];
                    Encoding.UTF8.GetBytes(resp, 0, resp.Length, buf, 0);
                    buf[size] = 10;
                    pipe.Write(buf, 0, buf.Length);
                    pipe.Flush();
                }
                finally { if (buf != null) Array.Clear(buf, 0, buf.Length); Secure.Wipe(resp); }
            }
            catch { }
        }

        // Bounded frame and deadline even for an authenticated browser bridge.
        static string ReadRequest(NamedPipeServerStream pipe)
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var bytes = new byte[1024];
            using (var data = new MemoryStream())
            {
                while (data.Length < BrowserPipe.MaxRequestBytes)
                {
                    int remaining = 5000 - (int)clock.ElapsedMilliseconds;
                    if (remaining <= 0) return null;
                    var read = pipe.BeginRead(bytes, 0, Math.Min(bytes.Length, BrowserPipe.MaxRequestBytes - (int)data.Length), null, null);
                    using (var done = read.AsyncWaitHandle)
                    {
                        if (!done.WaitOne(remaining)) { pipe.Dispose(); return null; }
                        int n = pipe.EndRead(read);
                        if (n == 0) return null;
                        int end = Array.IndexOf(bytes, (byte)'\n', 0, n);
                        data.Write(bytes, 0, end >= 0 ? end : n);
                        if (end >= 0) return new UTF8Encoding(false, true).GetString(data.ToArray());
                    }
                }
            }
            return null;
        }

        string Dispatch(string json)
        {
            Dictionary<string, object> d;
            try { d = new JavaScriptSerializer { MaxJsonLength = BrowserPipe.MaxRequestBytes }.Deserialize<Dictionary<string, object>>(json); }
            catch { return Err("bad_request"); }
            if (d == null) return Err("bad_request");
            object o;
            string type = d.TryGetValue("type", out o) ? o as string : null;
            string token = d.TryGetValue("token", out o) && o != null ? o.ToString() : null;

            // Сопряжение и состояние доступны без открытой базы.
            if (type == "status") return Status(token);
            if (type == "pair")
            {
                string browser = d.TryGetValue("browser", out o) && o != null ? o.ToString() : "браузер";
                return Pair(token, browser);
            }
            if (type == "unlock") return Unlock(token);

            if (type != "list" && type != "search" && type != "fill" && type != "otp-list" && type != "otp" && type != "otp-fill" && type != "otp-copy" &&
                type != "passkey-create" && type != "passkey-get" && type != "passkey-cancel") return Err("bad_request");
            if (!BrowserPair.IsPaired(token)) return Err("not_paired");
            if (type != "fill" && type != "otp-fill" && lookups.Hit(BrowserPair.HashToken(token)) > LookupsPerMinute) return Err("rate_limited");

            if (type.StartsWith("passkey-", StringComparison.Ordinal)) return PasskeyRequest(token, type, d);

            if (type == "otp-list") return OtpList(token, d.TryGetValue("query", out o) ? o as string : null);
            if (type == "otp" || type == "otp-fill" || type == "otp-copy")
                return OtpValue(token, d.TryGetValue("id", out o) ? o as string : null,
                    type == "otp-fill" ? (d.TryGetValue("url", out o) ? o as string : null) : null,
                    type == "otp-fill", type == "otp-copy", d.TryGetValue("generation", out o) && o is int ? (int)o : -1);

            string url = d.TryGetValue("url", out o) && o != null ? o.ToString() : null;
            if (type == "fill")
            {
                string id = d.TryGetValue("id", out o) && o != null ? o.ToString() : null;
                bool framed = d.TryGetValue("framed", out o) && o is bool && (bool)o;
                return Fill(token, url, id, framed);
            }
            string query = d.TryGetValue("query", out o) && o != null ? o.ToString() : "";
            return type == "list" ? ListOrSearch(token, url, null) : ListOrSearch(token, url, query);
        }

        static string Err(string error)
        {
            return "{\"ok\":false,\"error\":" + new JavaScriptSerializer().Serialize(error) + "}";
        }

        string PasskeyRequest(string token, string type, Dictionary<string, object> request)
        {
            object value;
            string id = request.TryGetValue("requestId", out value) ? value as string : null;
            if (id == null || id.Length != 32 || id.Any(c => !Uri.IsHexDigit(c))) return Err("bad_request");
            string key = BrowserPair.HashToken(token) + ":" + id;
            lock (cancelledPasskeys)
            {
                foreach (string old in cancelledPasskeys.Where(x => DateTime.UtcNow - x.Value > TimeSpan.FromMinutes(3)).Select(x => x.Key).ToArray()) cancelledPasskeys.Remove(old);
                foreach (string old in usedPasskeyRequests.Where(x => DateTime.UtcNow - x.Value > TimeSpan.FromMinutes(3)).Select(x => x.Key).ToArray()) usedPasskeyRequests.Remove(old);
                if (type == "passkey-cancel")
                {
                    if (cancelledPasskeys.Count >= 256) return Err("rate_limited");
                    cancelledPasskeys[key] = DateTime.UtcNow; return "{\"ok\":true}";
                }
                if (usedPasskeyRequests.ContainsKey(key) || usedPasskeyRequests.Count >= 256) return Err("bad_request");
                usedPasskeyRequests[key] = DateTime.UtcNow;
            }
            if (request.TryGetValue("framed", out value) && value is bool && (bool)value) return Err("SecurityError");
            string url = request.TryGetValue("url", out value) ? value as string : null;
            var options = request.TryGetValue("publicKey", out value) ? value as Dictionary<string, object> : null;
            var deadline = DateTime.UtcNow.AddSeconds(120);
            Func<bool> cancelled = delegate {
                if (stop || DateTime.UtcNow > deadline || !BrowserPair.IsPaired(token)) return true;
                lock (cancelledPasskeys) return cancelledPasskeys.ContainsKey(key);
            };
            string response = Err("host_error");
            RunUi(delegate {
                if (cancelled()) { response = Err("AbortError"); return; }
                if (askOpen) { response = Err("busy"); return; }
                askOpen = true;
                try {
                    using (var cancelTimer = new System.Windows.Forms.Timer { Interval = 100 }) {
                        cancelTimer.Tick += delegate {
                            if (cancelled()) foreach (var form in Application.OpenForms.Cast<Form>().ToArray())
                                if (form != owner && form.Owner == owner && form is ILockableDialog) form.Close();
                        };
                        cancelTimer.Start();
                        response = owner.BrowserPasskey(url, type == "passkey-create", options, cancelled);
                    }
                }
                catch { response = Err("host_error"); }
                finally { askOpen = false; }
            });
            return response;
        }

        string Status(string token)
        {
            bool open = false;
            int generation = 0;
            RunUi(delegate { open = owner.VaultNow != null; generation = owner.BrowserGeneration; });
            bool paired = BrowserPair.IsPaired(token);
            return "{\"ok\":true,\"state\":\"" + (open ? "open" : "locked") + "\",\"paired\":" + (paired ? "true" : "false") + ",\"generation\":" + generation + "}";
        }

        // One native host per open popup. Changes are pushed; heartbeats detect a dead peer.
        bool WatchRequest(NamedPipeServerStream pipe, string json)
        {
            Dictionary<string, object> d;
            try { d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json); }
            catch { return false; }
            object o;
            if (d == null || !d.TryGetValue("type", out o) || o as string != "watch") return false;
            string token = d.TryGetValue("token", out o) ? o as string : null;
            string key = BrowserPair.HashToken(token)+":"+Guid.NewGuid().ToString("N");
            bool admitted = false;
            lock (watchers) { if (watchers.Count < 8) admitted = watchers.Add(key); }
            try
            {
                using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1024, true) { AutoFlush = true })
                {
                    if (!admitted) { writer.WriteLine(Err("busy")); return true; }
                    string previous = null;
                    var heartbeat = DateTime.MinValue;
                    // The bridge writes exactly one request. A completed subsequent
                    // read means EOF (popup closed) or a forbidden extra request.
                    var disconnected=pipe.BeginRead(new byte[1],0,1,null,null);
                    try { while (!stop && !disconnected.IsCompleted)
                    {
                        if (!BrowserPair.IsPaired(token)) { writer.WriteLine(Err("not_paired")); break; }
                        string current = Status(token);
                        if (current != previous || DateTime.UtcNow - heartbeat > TimeSpan.FromSeconds(5))
                        { writer.WriteLine(current); previous = current; heartbeat = DateTime.UtcNow; }
                        Thread.Sleep(200);
                    }} finally { pipe.Dispose(); try { pipe.EndRead(disconnected); } catch { } }
                }
            }
            finally { if (admitted) lock (watchers) watchers.Remove(key); }
            return true;
        }

        string OtpList(string token, string query)
        {
            string response = Err("host_error");
            RunUi(delegate
            {
                var v = owner.VaultNow;
                if (v == null) { response = Err("locked"); return; }
                if (!BrowserPair.IsPaired(token)) { response = Err("not_paired"); return; }
                var q = (query ?? "").Trim();
                var items = v.Otp.Where(x => q.Length == 0 || x.Title.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0)
                    .Take(100).Select(x => new { id = x.Id, name = x.Issuer ?? "", login = x.Account ?? "" }).ToArray();
                response = new JavaScriptSerializer().Serialize(new { ok = true, items = items });
            });
            return response;
        }

        string OtpValue(string token, string id, string url, bool insert, bool copy, int generation)
        {
            if (string.IsNullOrEmpty(id)) return Err("bad_request");
            string host = insert ? SiteDomain.HostOf(url) : null;
            if (insert && (host == null || SiteDomain.IsHttpUrl(url))) return Err("insecure");
            string response = Err("host_error");
            RunUi(delegate
            {
                var v = owner.VaultNow;
                if (v == null) { response = Err("locked"); return; }
                if (copy && generation != owner.BrowserGeneration) { response = Err("locked"); return; }
                if (!BrowserPair.IsPaired(token)) { response = Err("not_paired"); return; }
                var otp = v.Otp.Find(x => x.Id == id);
                // A site card can refer to a linked authenticator without exposing its seed.
                if (otp == null)
                {
                    var entry = v.Entries.Find(x => x.Id == id && x.TwoFa == "link");
                    if (entry != null) otp = v.Otp.Find(x => x.Id == entry.OtpId);
                }
                if (otp == null) { response = Err("not_found"); return; }
                if (insert)
                {
                    if (askOpen) { response = Err("busy"); return; }
                    askOpen = true;
                    try
                    {
                        Win.Focus(owner.Handle);
                        if (MessageBox.Show(owner, "Вставить код 2FA «" + otp.Title + "» на сайте " + host + "?\n\nПроверьте адрес сайта.",
                            "WinUp — код 2FA", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                        { response = Err("denied"); return; }
                    }
                    finally { askOpen = false; }
                    if (owner.VaultNow != v) { response = Err("locked"); return; }
                    if (!BrowserPair.IsPaired(token)) { response = Err("not_paired"); return; }
                    if (!v.Otp.Contains(otp)) { response = Err("not_found"); return; }
                }
                try
                {
                    long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    int period = otp.Period > 0 ? otp.Period : 30;
                    string code = otp.UseSecret(s => Totp.Code(s, otp.Algorithm, otp.Digits, period, now / 1000));
                    try {
                        if (copy) { SecureClip.Copy(code); response = "{\"ok\":true}"; return; }
                        response = new JavaScriptSerializer().Serialize(new { ok = true, otp = code, id = otp.Id,
                        name = otp.Title, period = period, serverTime = now, expiresAt = (now / (period * 1000L) + 1) * period * 1000L,
                        generation = owner.BrowserGeneration }); }
                    finally { Secure.Wipe(code); }
                }
                catch { response = Err("invalid_otp"); }
            });
            return response;
        }

        string Pair(string token, string browser)
        {
            if (string.IsNullOrEmpty(token)) return Err("bad_request");
            string code = BrowserPair.CodeOf(token);
            bool allowed = false;
            string error = null;
            RunUi(delegate
            {
                if (askOpen) { error = "busy"; return; }
                if (DateTime.UtcNow - pairDeniedAt < TimeSpan.FromSeconds(PairCooldownSeconds)) { error = "rate_limited"; return; }
                owner.PwLog("Расширение: запрос сопряжения от «" + browser + "».");
                askOpen = true;
                try
                {
                    Win.Focus(owner.Handle);
                    allowed = MessageBox.Show(owner,
                        "Браузер «" + browser + "» просит доступ к паролям WinUp.\n\n" +
                        "Код сопряжения:  " + code + "\n\n" +
                        "Сверьте этот код с кодом в окне расширения.\nКоды совпадают и это ваш браузер?",
                        "WinUp — расширение браузера", MessageBoxButtons.YesNo, MessageBoxIcon.Question)
                        == DialogResult.Yes;
                }
                finally { askOpen = false; }
                if (allowed)
                {
                    BrowserPair.Save(token, browser);
                    owner.PwLog("Расширение: браузер «" + browser + "» связан с WinUp.");
                }
                else
                {
                    pairDeniedAt = DateTime.UtcNow;
                    owner.PwLog("Расширение: сопряжение с «" + browser + "» отклонено. Новые запросы сопряжения — не раньше чем через " +
                                PairCooldownSeconds + " с.");
                }
            });
            if (error != null) return Err(error);
            if (!allowed) return Err("denied");
            return "{\"ok\":true}";
        }

        string Unlock(string token)
        {
            if (!BrowserPair.IsPaired(token)) return Err("not_paired");
            // Вывод окна WinUp вперёд — не чаще раза в 3 с: повторяющиеся запросы не должны дёргать фокус.
            lock (this)
            {
                if (DateTime.UtcNow - lastUnlock < TimeSpan.FromSeconds(3)) return Err("rate_limited");
                lastUnlock = DateTime.UtcNow;
            }
            owner.BeginInvoke((MethodInvoker)delegate
            {
                Win.Focus(owner.Handle); // окно в этом же процессе: ActivateMainWindow ищет только чужие
                owner.UnlockBrowser();
            });
            return "{\"ok\":true}";
        }

        // list (query == null): записи этого сайта; search: все записи-сайты по запросу.
        string ListOrSearch(string token, string url, string query)
        {
            var pageHost = SiteDomain.HostOf(url);
            if (pageHost == null) return Err("bad_request");
            List<object> items = null;
            string error = null;
            RunUi(delegate
            {
                var v = owner.VaultNow;
                if (v == null) { error = "locked"; return; }
                items = new List<object>();
                foreach (var e in v.Entries)
                {
                    if (e.Kind != "site") continue;
                    var host = SiteDomain.HostOf(e.Target);
                    if (host == null) continue;
                    if (query != null)
                    {
                        // Поиск — только записи, подходящие под запрос (имя/адрес/логин);
                        // записи этого сайта не добавляются автоматически.
                        var q = query.Trim().ToLowerInvariant();
                        if (q.Length < 1) continue;
                        if (!((e.Name ?? "").ToLowerInvariant().Contains(q) ||
                              (e.Target ?? "").ToLowerInvariant().Contains(q) ||
                              (e.Login ?? "").ToLowerInvariant().Contains(q))) continue;
                        if (items.Count >= 30) return;
                    }
                    else if (!SiteDomain.SameSite(host, pageHost)) continue;
                    items.Add(Item(e, host, SiteDomain.SameSite(host, pageHost), SiteDomain.SameHost(host, pageHost) || BrowserAllow.Has(e.Id, pageHost)));
                }
            });
            if (error != null) return Err(error);
            var ser = new JavaScriptSerializer();
            return "{\"ok\":true,\"items\":" + ser.Serialize(items ?? new List<object>()) + "}";
        }

        static Dictionary<string, object> Item(LoginEntry e, string host, bool match, bool exact)
        {
            return new Dictionary<string, object>
            {
                { "id", e.Id }, { "name", e.Name ?? "" }, { "login", e.Login ?? "" },
                { "otp", e.TwoFa == "link" && !string.IsNullOrEmpty(e.OtpId) },
                { "match", match }, { "exact", exact }, { "site", host }
            };
        }

        string Fill(string token, string url, string id, bool framed)
        {
            if (string.IsNullOrEmpty(id)) return Err("bad_request");
            var pageHost = SiteDomain.HostOf(url);
            if (pageHost == null) return Err("bad_request");

            string error = null;
            KdbxStore authorizedVault = null;
            LoginEntry authorizedEntry = null;
            string authorizedTarget = null;
            bool hasOtp = false;
            int otpPeriod = 0;
            int recent = fills.Hit(BrowserPair.HashToken(token)); // запросов пароля за минуту вместе с этим
            if (!RunUi(delegate
            {
                var v = owner.VaultNow;
                if (v == null) { error = "locked"; return; }
                var e = v.Entries.Find(x => x.Id == id && x.Kind == "site");
                if (e == null) { error = "not_found"; return; }
                var host = SiteDomain.HostOf(e.Target);
                if (host == null) { error = "not_found"; return; }

                // Открытая http-страница не получает пароль от https-сайта. Проверка до вопроса пользователю:
                // спрашивать «Вставить?», чтобы потом всё равно отказать, бессмысленно.
                if (SiteDomain.IsHttpUrl(url) && !(e.Target ?? "").TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                { error = "insecure"; return; }

                // Без вопроса — только точный адрес записи (www. не в счёт) вне чужого фрейма или адрес, который
                // пользователь уже разрешил для этой записи. Поддомен того же сайта, другой сайт, чужой фрейм —
                // подтверждение в окне WinUp (поддомены бывают с чужим содержимым, а фреймы — подставными).
                // Больше FillsWithoutQuestion паролей за минуту — необычно для человека: каждый следующий только
                // после подтверждения, даже на точном адресе записи.
                bool sameSite = SiteDomain.SameSite(host, pageHost);
                bool exact = SiteDomain.SameHost(host, pageHost);
                bool burst = recent > FillsWithoutQuestion;
                if (burst || framed || !exact && !(sameSite && BrowserAllow.Has(e.Id, pageHost)))
                {
                    if (askOpen) { error = "busy"; return; }
                    askOpen = true;
                    try
                    {
                        using (var dlg = new ConfirmFillDialog(pageHost, e.Name, host, sameSite, framed, burst ? recent : 0))
                        {
                            // Окно WinUp вперёд, иначе вопрос откроется за браузером, где пользователь только что щёлкнул.
                            Win.Focus(owner.Handle);
                            if (dlg.ShowDialog(owner) != DialogResult.OK) { error = "denied"; return; }
                            if (dlg.Remember) BrowserAllow.Add(e.Id, pageHost, e.Name);
                        }
                    }
                    finally { askOpen = false; }
                    // Пока окно было открыто, базу могли заблокировать (Win+L, простой, кнопка в уведомлении).
                    if (owner.VaultNow != v) { error = "locked"; return; }
                }

                authorizedVault = v;
                authorizedEntry = e;
                authorizedTarget = e.Target;
                if (e.TwoFa == "link" && !string.IsNullOrEmpty(e.OtpId))
                {
                    var o = v.Otp.Find(x => x.Id == e.OtpId);
                    if (o != null) { hasOtp = true; otpPeriod = o.Period; }
                }
            })) return Err("host_error");
            if (error != null) return Err(error);

            // Код 2FA на излёте окна (меньше 5 с) — ждём следующий. Ждём здесь, в потоке канала,
            // а не в потоке интерфейса: окно WinUp не должно замирать на эти секунды.
            if (hasOtp && Totp.SecondsLeftFor(otpPeriod) < 5)
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                while (Totp.SecondsLeftFor(otpPeriod) < 5 && sw.Elapsed.TotalSeconds < 35)
                {
                    bool stillOpen = false;
                    if (!RunUi(delegate { stillOpen = owner.VaultNow == authorizedVault; }) || !stillOpen) return Err("locked");
                    Thread.Sleep(250);
                }
            }

            // Recheck authorization after every wait. Snapshot and serialize on the UI thread,
            // before LockVault can erase strings or switch databases.
            string response = null;
            if (!RunUi(delegate
            {
                var v = owner.VaultNow;
                if (v == null || v != authorizedVault) { response = Err("locked"); return; }
                if (!BrowserPair.IsPaired(token)) { response = Err("not_paired"); return; }
                var e = v.Entries.Find(x => x.Id == id && x.Kind == "site");
                if (e == null) { response = Err("not_found"); return; }
                // An editor can change or replace the entry while OTP generation waits.
                // The earlier site confirmation then no longer authorizes this response.
                if (!ReferenceEquals(e, authorizedEntry) || !string.Equals(e.Target, authorizedTarget, StringComparison.Ordinal))
                { response = Err("denied"); return; }
                var o = e.TwoFa == "link" ? v.Otp.Find(x => x.Id == e.OtpId) : null;
                response = e.UsePassword(pw =>
                {
                    var r = new Dictionary<string, object> { { "ok", true }, { "login", e.Login ?? "" }, { "password", pw ?? "" } };
                    if (o != null) r["otp"] = Totp.Code(o);
                    return new JavaScriptSerializer().Serialize(r);
                });
                owner.PwLog("Расширение: пароль записи «" + e.Name + "» выдан для сайта " + pageHost + ".");
                owner.NotifyFill(e.Name, pageHost);
            })) return Err("host_error");
            return response ?? Err("host_error");
        }

        // Выполнить в потоке интерфейса и дождаться (диалоги и база требуют последовательного доступа;
        // мост ждёт ответа столько, сколько нужно пользователю).
        bool RunUi(Action a)
        {
            try
            {
                if (owner.IsHandleCreated)
                {
                    if (owner.InvokeRequired) owner.Invoke((MethodInvoker)delegate { a(); });
                    else a();
                    return true;
                }
            }
            catch { }
            return false;
        }
    }

    // Разрешения «на этом адресе вставлять эту запись без вопроса»: HKCU\Software\WinUp\Browser\Allowed,
    // имя значения — SHA-256(id записи | адрес страницы). Только для того же сайта (поддомены), не для чужих.
    static class BrowserAllow
    {
        const string Key = @"Software\WinUp\Browser\Allowed";

        static string Name(string entryId, string pageHost) { return BrowserPair.HashToken((entryId ?? "") + "|" + (pageHost ?? "")); }

        public static bool Has(string entryId, string pageHost)
        {
            try { using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(Key)) return k != null && k.GetValue(Name(entryId, pageHost)) != null; }
            catch { return false; }
        }

        public static void Add(string entryId, string pageHost, string entryName)
        {
            using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(Key))
                k.SetValue(Name(entryId, pageHost), (entryName ?? "") + " → " + pageHost + " | " + DateTime.Now.ToString("dd.MM.yyyy"));
        }

        public static void Clear()
        {
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(Key, false); } catch { }
        }
    }

    // Подтверждение вставки: страница не на точном адресе записи (поддомен, другой сайт, чужой фрейм).
    class ConfirmFillDialog : Dlg, ILockableDialog
    {
        readonly CheckBox remember = new CheckBox { AutoSize = true, MaximumSize = new Size(460, 0) };
        public bool Remember { get { return remember.Enabled && remember.Checked; } }

        // burst > 0 — столько паролей запрошено за последнюю минуту (больше обычного).
        public ConfirmFillDialog(string pageHost, string entryName, string entryHost, bool sameSite, bool framed, int burst)
            : base("WinUp — вставить пароль?")
        {
            Note("Страница " + pageHost + " просит логин и пароль записи «" + entryName + "».");
            bool exact = SiteDomain.SameHost(entryHost, pageHost);
            Note("Адрес записи: " + entryHost + (exact ? "" : sameSite ? " (тот же сайт, другой адрес)" : " — ЭТО ДРУГОЙ САЙТ"),
                 sameSite ? SystemColors.GrayText : Color.Firebrick);
            if (framed)
                Note("Форма входа встроена в страницу другого сайта (фрейм) — такие формы бывают подставными.", Color.Firebrick);
            if (burst > 0)
                Note("За последнюю минуту браузер запросил паролей: " + burst + ". Обычно человек входит реже — " +
                     "если вы сейчас не входите на сайты один за другим, нажмите «Не вставлять».", Color.Firebrick);
            Note("Вставляйте, только если сами открыли этот сайт и узнаёте адрес.", SystemColors.GrayText);
            remember.Text = "Больше не спрашивать для «" + entryName + "» на " + pageHost;
            remember.Enabled = sameSite && !framed && !exact;
            remember.Visible = !exact;
            Grid.Controls.Add(remember); Grid.SetColumnSpan(remember, 2);
            Buttons();
            Ok.Text = "Вставить";
            Cancel.Text = "Не вставлять";
            AcceptButton = null; // Enter не должен подтверждать случайно — только явный щелчок
        }
    }

    // Окно «Меню → Расширение для браузера...»: подключение расширения и список сопряжённых браузеров.
    class PairedItem
    {
        public string Hash, Text;
        public override string ToString() { return Text; }
    }

    class BrowserDialog : Dlg
    {
        readonly TextBox dirBox = new TextBox { ReadOnly = true, Dock = DockStyle.Fill };
        readonly Label state = new Label { AutoSize = true, MaximumSize = new System.Drawing.Size(580, 0), ForeColor = SystemColors.GrayText };
        readonly ListBox paired = new ListBox { Dock = DockStyle.Fill, Height = 90, IntegralHeight = false };
        readonly Button forget = new Button { Text = "Забыть", AutoSize = true };
        readonly CheckBox notify = new CheckBox { AutoSize = true, MaximumSize = new Size(580, 0), Margin = new Padding(3, 6, 3, 6),
            Text = "Уведомлять в углу экрана о каждой вставке пароля" };

        public BrowserDialog()
            : base("WinUp — расширение для браузера")
        {
            Ok.Text = "Закрыть";
            Cancel.Visible = false;

            Note("Расширение показывает значок WinUp в полях входа на сайтах: щелчок по значку — " +
                 "список учётных записей этого сайта и вставка логина, пароля и кода 2FA. " +
                 "Пароли остаются в базе WinUp, расширение их не хранит.");
            Note("Подключение:", null);
            Note("1. Нажмите «Подключить» — WinUp скопирует расширение и зарегистрирует мост для " +
                 "Chrome, Edge, Яндекс Браузера и Brave (WinUp отвечает только браузеру с подписью его издателя).", SystemColors.GrayText);
            Note("2. В браузере откройте страницу расширений (адрес chrome://extensions, в Edge — edge://extensions).",
                 SystemColors.GrayText);
            Note("3. Включите «Режим разработчика».", SystemColors.GrayText);
            Note("4. Нажмите «Загрузить распакованное расширение» и выберите папку ниже. " +
                 "Папка общая для всех браузеров: она не рядом с WinUp.exe и не зависит от флешки.",
                 SystemColors.GrayText);
            Row("Папка:", dirBox);
            Grid.Controls.Add(state); Grid.SetColumnSpan(state, 2);
            notify.Checked = MainForm.FillNotifyEnabled;
            notify.CheckedChanged += (s, e) =>
            {
                var f = Owner as MainForm;
                if (f != null) f.SetFillNotify(notify.Checked);
            };
            Grid.Controls.Add(notify); Grid.SetColumnSpan(notify, 2);
            Note("Сопряжённые браузеры (код подтверждается в окне WinUp при первой связи):", null);
            paired.SelectedIndexChanged += (s, e) => { forget.Enabled = paired.SelectedItem != null; };
            Grid.Controls.Add(paired);
            Grid.SetColumnSpan(paired, 2);

            var open = new Button { Text = "Открыть папку", AutoSize = true };
            var copy = new Button { Text = "Скопировать путь", AutoSize = true };
            var connect = new Button { Text = "Подключить", AutoSize = true };
            var off = new Button { Text = "Отключить", AutoSize = true };
            connect.Click += (s, e) =>
            {
                try
                {
                    BrowserSetup.Connect();
                    Log("Расширение браузера: подключено (папка " + BrowserSetup.BrowserDir + ").");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Не удалось подготовить расширение:\n" + ex.Message, "WinUp",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                RefreshAll();
                MessageBox.Show(this, "Готово. Теперь в браузере:\n\n" +
                    "1) откройте страницу расширений (chrome://extensions);\n" +
                    "2) включите «Режим разработчика»;\n" +
                    "3) «Загрузить распакованное расширение» и выберите папку\n" + BrowserSetup.BrowserDir + "\n\n" +
                    "Уже открытые браузеры увидят WinUp после перезапуска.",
                    "WinUp — расширение браузера", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            off.Click += (s, e) =>
            {
                if (MessageBox.Show(this, "Отключить расширение? WinUp удалит свою копию расширения и регистрацию моста.\n" +
                    "Сопряжённые браузеры можно забыть отдельно ниже.",
                    "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                try { BrowserSetup.Disconnect(); Log("Расширение браузера: отключено."); }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Не удалось отключить:\n" + ex.Message, "WinUp",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                RefreshAll();
            };
            open.Click += (s, e) =>
            {
                try
                {
                    if (!Directory.Exists(BrowserSetup.BrowserDir)) BrowserSetup.Connect();
                    System.Diagnostics.Process.Start(BrowserSetup.BrowserDir);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Не удалось открыть папку:\n" + ex.Message, "WinUp",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };
            copy.Click += (s, e) =>
            {
                try { Clipboard.SetText(BrowserSetup.BrowserDir); copy.Text = "Скопировано"; }
                catch { }
            };
            forget.Click += (s, e) =>
            {
                var it = paired.SelectedItem as PairedItem;
                if (it == null) return;
                BrowserPair.Forget(it.Hash);
                Log("Расширение браузера: браузер забыт (сопряжение снято).");
                RefreshAll();
            };
            var resetAllow = new Button { Text = "Сбросить разрешённые адреса", AutoSize = true };
            resetAllow.Click += (s, e) =>
            {
                BrowserAllow.Clear();
                Log("Расширение браузера: разрешённые адреса сброшены — на поддоменах WinUp снова будет спрашивать.");
                resetAllow.Text = "Сброшено";
            };
            Buttons(connect, off, forget, open, copy, resetAllow);
            RefreshAll();
        }

        void Log(string m)
        {
            var f = Owner as MainForm;
            if (f != null) f.PwLogAsync(m);
        }

        void RefreshAll()
        {
            dirBox.Text = BrowserSetup.BrowserDir;
            bool on = BrowserSetup.Enabled;
            state.Text = on
                ? "Подключено. Путь к WinUp.exe обновляется при каждом запуске программы."
                : "Не подключено. Нажмите «Подключить».";
            state.ForeColor = on ? SystemColors.GrayText : Color.Firebrick;
            paired.Items.Clear();
            foreach (var kv in BrowserPair.List())
                paired.Items.Add(new PairedItem { Hash = kv.Key, Text = kv.Value });
            forget.Enabled = paired.SelectedItem != null;
        }
    }
}

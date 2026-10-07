using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace WinUp
{
    // Защита канала мост↔окно (см. Browser.cs).
    // Окно WinUp отвечает только мосту — этому же WinUp.exe, запущенному браузером с действительной
    // цифровой подписью его издателя. Мост отправляет запрос (в нём токен сопряжения) только окну
    // из этого же WinUp.exe: канал с тем же именем, созданный другой программой, токен не получит.
    static class Proc
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, int pid);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32 e);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32 e);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sec, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(IntPtr h, out BY_HANDLE_FILE_INFORMATION info);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32
        {
            public uint dwSize, cntUsage; public int th32ProcessID; public IntPtr th32DefaultHeapID;
            public uint th32ModuleID, cntThreads; public int th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct BY_HANDLE_FILE_INFORMATION
        {
            public uint Attributes; public long Created, Accessed, Written;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        const uint QueryLimited = 0x1000;
        static readonly IntPtr Invalid = new IntPtr(-1);

        internal sealed class ProcessIdentity
        {
            internal string Path;
            internal long Started;
        }

        // Read both values from the same kernel process object. Separate PID
        // lookups could combine the old process path with a reused PID's time.
        internal static ProcessIdentity Identity(int pid)
        {
            if(pid<=0) return null;
            var handle=OpenProcess(QueryLimited,false,pid);
            if(handle==IntPtr.Zero) return null;
            try {
                var name=new StringBuilder(1024); int length=name.Capacity;
                long created,exited,kernel,user;
                if(!QueryFullProcessImageName(handle,0,name,ref length) ||
                    !GetProcessTimes(handle,out created,out exited,out kernel,out user) || created==0 || exited!=0) return null;
                return new ProcessIdentity { Path=name.ToString(0,length),Started=created };
            } finally { CloseHandle(handle); }
        }

        public static int ClientPid(PipeStream p)
        {
            uint pid;
            return GetNamedPipeClientProcessId(p.SafePipeHandle.DangerousGetHandle(), out pid) ? (int)pid : 0;
        }

        public static int ServerPid(PipeStream p)
        {
            uint pid;
            return GetNamedPipeServerProcessId(p.SafePipeHandle.DangerousGetHandle(), out pid) ? (int)pid : 0;
        }

        // Полный путь exe процесса; null, если процесса нет или доступ закрыт.
        public static string ImagePath(int pid)
        {
            if (pid <= 0) return null;
            var h = OpenProcess(QueryLimited, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(1024);
                int n = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString(0, n) : null;
            }
            finally { CloseHandle(h); }
        }

        // Время запуска процесса (FILETIME); 0 — неизвестно.
        public static long StartTime(int pid)
        {
            if (pid <= 0) return 0;
            var h = OpenProcess(QueryLimited, false, pid);
            if (h == IntPtr.Zero) return 0;
            try
            {
                long c, x, k, u;
                return GetProcessTimes(h, out c, out x, out k, out u) ? c : 0;
            }
            finally { CloseHandle(h); }
        }

        // Номер родительского процесса из снимка процессов; 0 — не найден.
        public static int ParentPid(int pid)
        {
            var snap = CreateToolhelp32Snapshot(2 /* TH32CS_SNAPPROCESS */, 0);
            if (snap == Invalid || snap == IntPtr.Zero) return 0;
            try
            {
                var e = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32)) };
                if (!Process32FirstW(snap, ref e)) return 0;
                do { if (e.th32ProcessID == pid) return e.th32ParentProcessID; }
                while (Process32NextW(snap, ref e));
                return 0;
            }
            finally { CloseHandle(snap); }
        }

        // Один и тот же файл: путь совпадает или совпадают том и номер файла (короткие имена 8.3, subst, регистр).
        public static bool SameFile(string a, string b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
            try { if (string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase)) return true; }
            catch { return false; }
            BY_HANDLE_FILE_INFORMATION ia, ib;
            return FileId(a, out ia) && FileId(b, out ib) &&
                   ia.VolumeSerial == ib.VolumeSerial && ia.IndexHigh == ib.IndexHigh && ia.IndexLow == ib.IndexLow;
        }

        static bool FileId(string path, out BY_HANDLE_FILE_INFORMATION info)
        {
            info = new BY_HANDLE_FILE_INFORMATION();
            var h = CreateFile(path, 0x80 /* FILE_READ_ATTRIBUTES */, 7 /* share all */, IntPtr.Zero, 3 /* OPEN_EXISTING */, 0, IntPtr.Zero);
            if (h == Invalid) return false;
            try { return GetFileInformationByHandle(h, out info); }
            finally { CloseHandle(h); }
        }
    }

    // Подпись Authenticode: файл подписан, подпись действительна, издатель — ожидаемая организация.
    static class Signature
    {
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO { public uint cbStruct; public string pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct; public IntPtr pPolicyCallbackData, pSIPClientData;
            public uint dwUIChoice, fdwRevocationChecks, dwUnionChoice;
            public IntPtr pFile; public uint dwStateAction; public IntPtr hWVTStateData, pwszURLReference;
            public uint dwProvFlags, dwUIContext; public IntPtr pSignatureSettings;
        }

        static Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        public static bool SignedBy(string path, string org)
        {
            // Metadata is attacker controlled: replacing a once trusted file while
            // preserving its timestamp/length must never reuse the earlier verdict.
            // Hold a non-write/non-delete-sharing handle while both checks read it.
            try
            {
                using (var pinned = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    return Valid(path) && OrganizationMatches(OrgOf(path), org);
            }
            catch { return false; }
        }

        internal static bool OrganizationMatches(string actual, string expected)
        {
            string[] names;
            switch (expected)
            {
                case "Google": names = new[] { "Google LLC", "Google Inc" }; break;
                case "Microsoft": names = new[] { "Microsoft Corporation" }; break;
                case "Yandex": names = new[] { "Yandex LLC", "YANDEX LLC" }; break;
                case "Brave": names = new[] { "Brave Software, Inc." }; break;
                case "Opera": names = new[] { "Opera Norway AS", "Opera Software AS" }; break;
                case "Vivaldi": names = new[] { "Vivaldi Technologies AS" }; break;
                case "Mozilla": names = new[] { "Mozilla Corporation" }; break;
                default: return false;
            }
            return Array.Exists(names, name => string.Equals(actual, name, StringComparison.OrdinalIgnoreCase));
        }

        public static bool SignedByName(string path, string signer)
        {
            // Do not use the browser-signature cache for loadable code.
            try
            {
                if (!Valid(path)) return false;
                using (var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
                    return string.Equals(cert.GetNameInfo(X509NameType.SimpleName, false), signer, StringComparison.Ordinal);
            }
            catch { return false; }
        }

        // Действительность подписи без обращения к сети (отзыв сертификатов не проверяется: без интернета мост должен работать).
        static bool Valid(string path)
        {
            var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            try
            {
                Marshal.StructureToPtr(file, pFile, false);
                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    dwUIChoice = 2,            // WTD_UI_NONE
                    fdwRevocationChecks = 0,   // WTD_REVOKE_NONE
                    dwUnionChoice = 1,         // WTD_CHOICE_FILE
                    pFile = pFile,
                    dwStateAction = 1,         // WTD_STATEACTION_VERIFY
                    dwProvFlags = 0x1000 | 0x10 // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
                };
                int rc = WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, ref data);
                data.dwStateAction = 2;        // WTD_STATEACTION_CLOSE
                WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, ref data);
                return rc == 0;
            }
            catch { return false; }
            finally
            {
                Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(pFile);
            }
        }

        // Организация (O=) из сертификата подписавшего; "" — нет подписи.
        public static string OrgOf(string path)
        {
            try
            {
                var subject = X509Certificate.CreateFromSignedFile(path).Subject;
                var m = Regex.Match(subject, "(?:^|,\\s*)O=(\"(?<q>[^\"]*)\"|(?<v>[^,]*))");
                return m.Success ? (m.Groups["q"].Success ? m.Groups["q"].Value : m.Groups["v"].Value).Trim() : "";
            }
            catch { return ""; }
        }
    }

    // Кто прислал запрос в канал: мост WinUp, запущенный браузером. Chrome и Edge запускают мост
    // через cmd.exe (так устроен Native Messaging в Windows): мост → cmd.exe → браузер.
    static class BrowserCaller
    {
        // exe браузера → организация в его цифровой подписи. Браузеры без подписи (сборки Chromium) не допускаются:
        // по имени файла любую программу можно выдать за браузер.
        static readonly Dictionary<string, string> Known = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "chrome.exe", "Google" }, { "msedge.exe", "Microsoft" }, { "browser.exe", "Yandex" },
            { "brave.exe", "Brave" }, { "opera.exe", "Opera" }, { "vivaldi.exe", "Vivaldi" }, { "firefox.exe", "Mozilla" }
        };

        // null — запрос от моста, запущенного браузером; иначе причина отказа (для журнала).
        // Номер родителя проверяется по времени запуска: завершившийся родитель мог уступить номер другому процессу.
        public static string Check(int clientPid, out string browser)
        {
            browser = null;
            var self = System.Windows.Forms.Application.ExecutablePath;
            var client = Proc.Identity(clientPid);
            if (client == null) return "не удалось определить программу, приславшую запрос (процесс " + clientPid + ")";
            if (!Proc.SameFile(client.Path, self)) return "запрос прислал не мост WinUp, а " + client.Path;

            int pid = clientPid;
            long childStart = client.Started;
            var ancestry = new List<KeyValuePair<int,long>> { new KeyValuePair<int,long>(clientPid,client.Started) };
            for (int hop = 0; hop < 2; hop++)
            {
                int ppid = Proc.ParentPid(pid);
                var parent = Proc.Identity(ppid);
                long pstart = parent==null ? 0 : parent.Started;
                // Родитель завершён, а его номер занял другой процесс (запущенный позже моста), — цепочка не подтверждена.
                if (ppid <= 0 || pstart == 0 || childStart == 0 || pstart > childStart)
                    return "мост запущен не браузером (запустившая программа уже завершилась)";
                ancestry.Add(new KeyValuePair<int,long>(ppid,pstart));
                var ppath = parent==null ? null : parent.Path;
                if (ppath == null) return "мост запущен программой, которую WinUp не может проверить (процесс " + ppid + ")";
                var name = Path.GetFileName(ppath);
                if (hop == 0 && string.Equals(name, "cmd.exe", StringComparison.OrdinalIgnoreCase) &&
                    Proc.SameFile(ppath, Path.Combine(Environment.SystemDirectory, "cmd.exe")))
                {
                    pid = ppid; childStart = pstart;
                    continue;
                }
                string org;
                if (!Known.TryGetValue(name, out org)) return "мост запущен не браузером, а " + ppath;
                if (!Signature.SignedBy(ppath, org))
                    return "у программы " + ppath + " нет действительной подписи " + org + " — это не настоящий браузер";
                foreach(var ancestor in ancestry) {
                    var current=Proc.Identity(ancestor.Key);
                    if(current==null || current.Started!=ancestor.Value)
                        return "процесс моста или браузера завершился во время проверки";
                }
                browser = name;
                return null;
            }
            return "мост запущен не браузером";
        }

        // Окно на другом конце канала — этот же WinUp.exe (проверка на стороне моста). null — да.
        public static string CheckServer(PipeStream pipe)
        {
            var identity = Proc.Identity(Proc.ServerPid(pipe));
            var server = identity==null ? null : identity.Path;
            if (server == null) return "канал создан неизвестной программой";
            return Proc.SameFile(server, System.Windows.Forms.Application.ExecutablePath) ? null : "канал создан программой " + server;
        }
    }

    // Частота запросов в скользящем окне; ключ — хэш токена (у каждого браузера свой счёт).
    class RateWindow
    {
        readonly Dictionary<string, Queue<DateTime>> hits = new Dictionary<string, Queue<DateTime>>();
        readonly TimeSpan window;

        public RateWindow(TimeSpan window) { this.window = window; }

        // Учесть запрос; возвращает число запросов в окне вместе с этим.
        public int Hit(string key)
        {
            lock (hits)
            {
                Queue<DateTime> q;
                if (!hits.TryGetValue(key ?? "", out q)) hits[key ?? ""] = q = new Queue<DateTime>();
                var now = DateTime.UtcNow;
                while (q.Count > 0 && now - q.Peek() > window) q.Dequeue();
                q.Enqueue(now);
                return q.Count;
            }
        }
    }

    // Уведомление о выдаче пароля расширению: в углу экрана, без захвата фокуса (не мешает вводу на сайте).
    // Если вставляли не вы — «Заблокировать базу». Повторные выдачи обновляют то же окно.
    class FillToast : Form
    {
        static FillToast current;
        readonly Label head = new Label { AutoSize = true, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) };
        readonly Label body = new Label { AutoSize = true, MaximumSize = new Size(330, 0), Margin = new Padding(0, 4, 0, 0) };
        readonly Label hint = new Label { AutoSize = true, MaximumSize = new Size(330, 0), ForeColor = SystemColors.GrayText, Margin = new Padding(0, 4, 0, 0) };
        readonly Button lockBtn = new Button { Text = "Заблокировать базу", AutoSize = true };
        readonly Button closeBtn = new Button { Text = "Закрыть", AutoSize = true };
        readonly Timer timer = new Timer { Interval = 500 };
        readonly List<DateTime> times = new List<DateTime>();
        DateTime hideAt;
        Action onLock;

        public const int ShowSeconds = 8;

        // Показать или обновить уведомление. Вызывается в потоке интерфейса.
        public static void Notify(string entry, string site, Action onLock)
        {
            if (current == null || current.IsDisposed) current = new FillToast();
            current.onLock = onLock;
            current.Add(entry, site);
        }

        public static void CloseAll()
        {
            if (current != null && !current.IsDisposed) current.Close();
            current = null;
        }

        FillToast()
        {
            Text = "WinUp — пароль вставлен";
            Font = new Font("Segoe UI", 9f);
            FormBorderStyle = FormBorderStyle.FixedToolWindow;
            ControlBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            BackColor = SystemColors.Window;
            Padding = new Padding(12, 10, 12, 10);

            var col = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Dock = DockStyle.Fill };
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Margin = new Padding(0, 8, 0, 0) };
            bar.Controls.Add(lockBtn); bar.Controls.Add(closeBtn);
            col.Controls.Add(head); col.Controls.Add(body); col.Controls.Add(hint); col.Controls.Add(bar);
            Controls.Add(col);

            hint.Text = "Не вы вставляли? Заблокируйте базу и проверьте, кто управляет браузером.";
            lockBtn.Click += (s, e) =>
            {
                var a = onLock;
                if (a != null) a();
                head.Text = "База паролей заблокирована";
                body.Text = "Вставка паролей остановлена до ввода пароля базы.";
                hint.Text = "";
                lockBtn.Enabled = false;
                hideAt = DateTime.UtcNow.AddSeconds(4);
                Place();
            };
            closeBtn.Click += (s, e) => Close();
            timer.Tick += (s, e) =>
            {
                // Под указателем мыши не исчезает: пользователь читает или тянется к кнопке.
                if (Bounds.Contains(Cursor.Position)) { hideAt = DateTime.UtcNow.AddSeconds(2); return; }
                if (DateTime.UtcNow >= hideAt) Close();
            };
            FormClosed += (s, e) => { timer.Dispose(); if (current == this) current = null; };
        }

        // Без активации: фокус остаётся в браузере, в поле, куда только что вставлен пароль.
        protected override bool ShowWithoutActivation { get { return true; } }

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= 0x08000000 /* WS_EX_NOACTIVATE */ | 0x00000008 /* WS_EX_TOPMOST */;
                return cp;
            }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Win.ApplyCaptureProtection(this);
        }

        void Add(string entry, string site)
        {
            var now = DateTime.UtcNow;
            times.Add(now);
            times.RemoveAll(t => now - t > TimeSpan.FromMinutes(1));
            head.Text = "WinUp: пароль вставлен в браузере";
            body.Text = "«" + entry + "» → " + site +
                        (times.Count > 1 ? "\nЗа последнюю минуту выдано паролей: " + times.Count : "");
            lockBtn.Enabled = true;
            hideAt = now.AddSeconds(ShowSeconds);
            if (!Visible) { Place(); Show(); }
            else Place();
            timer.Start();
        }

        // Правый нижний угол экрана, на котором сейчас указатель (там браузер).
        void Place()
        {
            var wa = Screen.FromPoint(Cursor.Position).WorkingArea;
            var sz = GetPreferredSize(Size.Empty);
            Location = new Point(wa.Right - sz.Width - 12, wa.Bottom - sz.Height - 12);
        }
    }
}

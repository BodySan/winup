using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace WinUp
{
    // Работа с окнами и вводом. Ввод — Unicode-символами через SendInput: не зависит от раскладки.
    static class Win
    {
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int c);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int RegisterWindowMessage(string name);
        [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, int message, IntPtr w, IntPtr l);
        public static readonly int WmShowWinUp = RegisterWindowMessage("WinUp.ShowMainWindow.1");
        [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();

        // Уведомления о блокировке сеанса (Win+L): база паролей блокируется вместе с Windows.
        [DllImport("wtsapi32.dll")] static extern bool WTSRegisterSessionNotification(IntPtr hWnd, int flags);
        [DllImport("wtsapi32.dll")] static extern bool WTSUnRegisterSessionNotification(IntPtr hWnd);
        public static void SessionNotifyRegister(IntPtr hWnd) { try { WTSRegisterSessionNotification(hWnd, 0); } catch { } }
        public static void SessionNotifyUnregister(IntPtr hWnd) { try { WTSUnRegisterSessionNotification(hWnd); } catch { } }
        public const int WmWtsSessionChange = 0x02B1;
        public const int WtsSessionLock = 5;

        // Защита от записи экрана: окна WinUp исключаются из захвата (скриншоты, запись, AnyDesk/TeamViewer,
        // демонстрация экрана) — там вместо окна пусто. Windows 10 2004+; на более старых — WDA_MONITOR (чёрное окно).
        // Ввод чужой «удалённой мыши» Windows от вашего не отличает: защита в том, что окно с секретами не видно.
        [DllImport("user32.dll")] static extern bool SetWindowDisplayAffinity(IntPtr h, uint affinity);
        const uint WdaNone = 0, WdaMonitor = 1, WdaExcludeFromCapture = 0x11;
        public static bool CaptureProtection = true;

        public static void ApplyCaptureProtection(System.Windows.Forms.Form f)
        {
            try
            {
                if (f == null || !f.IsHandleCreated) return;
                if (!CaptureProtection) { SetWindowDisplayAffinity(f.Handle, WdaNone); return; }
                if (!SetWindowDisplayAffinity(f.Handle, WdaExcludeFromCapture)) SetWindowDisplayAffinity(f.Handle, WdaMonitor);
            }
            catch { }
        }

        // Включение/выключение на лету: применяется ко всем открытым окнам WinUp.
        public static void SetCaptureProtection(bool on)
        {
            CaptureProtection = on;
            foreach (System.Windows.Forms.Form f in System.Windows.Forms.Application.OpenForms) ApplyCaptureProtection(f);
        }
        [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);
        [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern bool BringWindowToTop(IntPtr h);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll")] static extern bool AttachThreadInput(uint a, uint b, bool attach);
        [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int max);
        [DllImport("user32.dll")] static extern int GetWindowTextLength(IntPtr h);
        delegate bool EnumProc(IntPtr h, IntPtr l);
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
        [DllImport("user32.dll", SetLastError = true)] static extern uint SendInput(uint n, INPUT[] inputs, int size);
        [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO info);

        [StructLayout(LayoutKind.Sequential)] struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
        [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr extra; }
        [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr extra; }
        [StructLayout(LayoutKind.Explicit)] struct InputUnion { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
        [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public InputUnion u; }

        const uint KEYUP = 2, UNICODE = 4;
        public const ushort TAB = 0x09, ENTER = 0x0D;

        // Отправляет нажатие+отпускание. false — SendInput не вставил события (например, UIPI:
        // целевое окно с правами администратора): молчаливый «успех» означал бы невведённый пароль.
        static bool Send(ushort vk, ushort scan, uint flags)
        {
            var a = new INPUT[2];
            a[0].type = 1; a[0].u.ki.wVk = vk; a[0].u.ki.wScan = scan; a[0].u.ki.dwFlags = flags;
            a[1] = a[0]; a[1].u.ki.dwFlags = flags | KEYUP;
            bool ok = SendInput(2, a, Marshal.SizeOf(typeof(INPUT))) == 2;
            Thread.Sleep(15);
            return ok;
        }

        // Ввод текста с проверкой перед каждым символом, что фокус по-прежнему в целевом окне:
        // если пользователь (или другое приложение) переключили фокус — пароль не уйдёт в чужое окно.
        // Возвращает false, если ввод прерван из-за смены фокуса или сбоя SendInput.
        public static bool TypeText(IntPtr target, string s)
        {
            if (s == null) return true;
            foreach (char c in s)
            {
                if (GetForegroundWindow() != target) return false;
                if (!Send(0, c, UNICODE)) return false;
            }
            return GetForegroundWindow() == target;
        }

        public static bool Key(IntPtr target, ushort vk)
        {
            if (GetForegroundWindow() != target) return false;
            return Send(vk, 0, 0);
        }

        public static bool IsForeground(IntPtr h) { return GetForegroundWindow() == h; }
        internal static IntPtr Foreground {get{return GetForegroundWindow();}}
        [DllImport("user32.dll")]static extern short GetAsyncKeyState(int key);
        internal static bool ModifiersReleased{get{return new[]{0x10,0x11,0x12}.All(k=>(GetAsyncKeyState(k)&0x8000)==0);}}
        static bool Modifier(ushort key,bool up){var input=new INPUT{type=1};input.u.ki.wVk=key;input.u.ki.dwFlags=up?KEYUP:0;return SendInput(1,new[]{input},Marshal.SizeOf(typeof(INPUT)))==1;}
        internal static bool Chord(IntPtr target,ushort key,bool control,bool shift){if(!IsForeground(target))return false;try{if(control&&!Modifier(0x11,false))return false;if(shift&&!Modifier(0x10,false))return false;return Key(target,key);}finally{if(shift)Modifier(0x10,true);if(control)Modifier(0x11,true);}}

        // Окно уже запущенного WinUp из этой же папки (другой процесс) — развернуть и вывести вперёд.
        public static bool ActivateMainWindow(string title)
        {
            uint self = (uint)Process.GetCurrentProcess().Id;
            IntPtr found = IntPtr.Zero;
            EnumWindows((h, l) =>
            {
                uint pid;
                GetWindowThreadProcessId(h, out pid);
                if (pid != self && Title(h) == title && Proc.SameFile(Proc.ImagePath((int)pid), System.Windows.Forms.Application.ExecutablePath))
                { found = h; return false; }
                return true;
            }, IntPtr.Zero);
            if (found == IntPtr.Zero) return false;
            PostMessage(found, WmShowWinUp, IntPtr.Zero, IntPtr.Zero);
            SetForegroundWindow(found);
            // Windows вправе отказать (запуск не от активного окна) — тогда вызывающий покажет сообщение.
            Thread.Sleep(150);
            return GetForegroundWindow() == found;
        }

        // Вывести окно на передний план без нажатия клавиш и проверить, что это удалось.
        public static bool Focus(IntPtr h)
        {
            if (IsIconic(h)) ShowWindow(h, 9);
            for (int i = 0; i < 5; i++)
            {
                uint pid;
                uint fg = GetWindowThreadProcessId(GetForegroundWindow(), out pid), me = GetCurrentThreadId();
                bool att = fg != me && AttachThreadInput(me, fg, true);
                BringWindowToTop(h); SetForegroundWindow(h);
                if (att) AttachThreadInput(me, fg, false);
                Thread.Sleep(150);
                if (GetForegroundWindow() == h) { Thread.Sleep(400); return true; } // окно успевает принять ввод
            }
            return false;
        }

        public static string Title(IntPtr h)
        {
            int n = GetWindowTextLength(h);
            if (n <= 0) return "";
            var sb = new StringBuilder(n + 1);
            GetWindowText(h, sb, sb.Capacity);
            return sb.ToString();
        }

        // Видимые окна с заголовком, кроме окон самого WinUp.
        public static List<KeyValuePair<IntPtr, string>> Windows()
        {
            uint self = (uint)Process.GetCurrentProcess().Id;
            var list = new List<KeyValuePair<IntPtr, string>>();
            EnumWindows((h, l) =>
            {
                uint pid;
                GetWindowThreadProcessId(h, out pid);
                if (pid != self && IsWindowVisible(h))
                {
                    var t = Title(h);
                    if (t.Length > 0) list.Add(new KeyValuePair<IntPtr, string>(h, t));
                }
                return true;
            }, IntPtr.Zero);
            return list;
        }

        // Окно, в заголовке которого есть любая из частей "a|b|c" (без учёта регистра).
        public static IntPtr Find(string spec)
        {
            return Find(spec,null);
        }

        public static IntPtr Find(string spec,Func<IntPtr,bool> predicate)
        {
            if (string.IsNullOrWhiteSpace(spec)) return IntPtr.Zero;
            var parts = spec.Split('|').Select(p => p.Trim()).Where(p => p.Length > 0).ToArray();
            foreach (var w in Windows())
                foreach (var p in parts)
                    if (w.Value.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0 && (predicate==null || predicate(w.Key))) return w.Key;
            return IntPtr.Zero;
        }

        public static TimeSpan Idle()
        {
            var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO)) };
            if (!GetLastInputInfo(ref info)) return TimeSpan.Zero;
            return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - info.dwTime));
        }

        public static bool IsAdmin()
        {
            using (var id = System.Security.Principal.WindowsIdentity.GetCurrent())
                return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
    }

    // Копирование секрета в буфер: не попадает в журнал буфера Windows (Win+V) и облачную синхронизацию,
    // помечено для менеджеров буфера как пароль; через N секунд буфер очищается, если там всё ещё он.
    // При блокировке базы и при выходе из приложения буфер очищается немедленно (ClearNow).
    // Оставить секрет в буфере может только жёсткое прерывание процесса (kill/power loss) —
    // это фундаментальное ограничение механизма буфера обмена Windows.
    static class SecureClip
    {
        static readonly SecretText last = new SecretText();
        static System.Windows.Forms.Timer timer;  // автоочистка через N секунд после Copy
        static System.Windows.Forms.Timer retry;  // повтор очистки, если буфер занят другой программой

        public static void Copy(string text, int seconds = 30)
        {
            var d = new System.Windows.Forms.DataObject();
            d.SetData(System.Windows.Forms.DataFormats.UnicodeText, text ?? "");
            d.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[] { 0 }));
            d.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
            d.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
            d.SetData("x-kde-passwordManagerHint", new MemoryStream(Encoding.ASCII.GetBytes("secret")));
            System.Windows.Forms.Clipboard.SetDataObject(d, true);
            // Независимая копия: строку-источник (поле записи) могут затереть при блокировке базы,
            // а сравнение для очистки буфера должно работать с настоящим содержимым.
            last.Set(text ?? "");
            // Новый Copy отменяет незавершившийся retry прошлой очистки: буфер уже перезаписан,
            // а оставленный retry очистил бы новый секрет сразу после копирования.
            if (retry != null) { retry.Stop(); retry.Dispose(); retry = null; }
            if (timer != null) { timer.Stop(); timer.Dispose(); }
            timer = new System.Windows.Forms.Timer { Interval = seconds * 1000 };
            timer.Tick += (s, e) =>
            {
                timer.Stop();
                ClearNow();
            };
            timer.Start();
        }

        // Одна попытка очистить буфер, если там всё ещё наш секрет. false — буфер занят другой программой.
        static bool TryClear()
        {
            try
            {
                if (last.HasValue && System.Windows.Forms.Clipboard.ContainsText())
                {
                    var current = System.Windows.Forms.Clipboard.GetText();
                    try { if (last.Use(text => current == text)) System.Windows.Forms.Clipboard.Clear(); }
                    finally { Secure.Wipe(current); }
                }
                return true;
            }
            catch { return false; }
        }

        // Секрета в буфере больше нет (или не было): затираем копию и останавливаем таймеры.
        static void Done()
        {
            last.Clear();
            if (timer != null) { timer.Stop(); timer.Dispose(); timer = null; }
            if (retry != null) { retry.Stop(); retry.Dispose(); retry = null; }
        }

        // Немедленно очистить буфер, если там всё ещё наш секрет. Вызывается при блокировке и при выходе.
        // Если буфер занят другой программой (исключение), раньше last затирался и таймер умирал —
        // секрет оставался в буфере навсегда. Теперь last сохраняется, и очистка повторяется по таймеру.
        public static void ClearNow()
        {
            if (last.HasValue && !TryClear())
            {
                if (retry == null)
                {
                    retry = new System.Windows.Forms.Timer { Interval = 2000 };
                    retry.Tick += (s, e) => { if (TryClear()) Done(); };
                }
                if (!retry.Enabled) retry.Start();
                return;
            }
            Done();
        }
    }

    public class BrowserInfo
    {
        public string Name;
        public string Exe;
    }

    // Установленные браузеры — из стандартного списка Windows (Clients\StartMenuInternet).
    static class Browsers
    {
        public static List<BrowserInfo> Installed()
        {
            var list = new List<BrowserInfo>();
            var roots = new[]
            {
                Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Clients\StartMenuInternet"),
                Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Clients\StartMenuInternet"),
                Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Clients\StartMenuInternet"),
            };
            foreach (var root in roots)
            {
                if (root == null) continue;
                using (root)
                    foreach (var sub in root.GetSubKeyNames())
                        using (var k = root.OpenSubKey(sub))
                        using (var cmd = k == null ? null : k.OpenSubKey(@"shell\open\command"))
                        {
                            var name = (k == null ? null : k.GetValue("") as string) ?? sub;
                            var exe = ExeFromCommand(cmd == null ? null : cmd.GetValue("") as string);
                            if (exe == null || !File.Exists(exe)) continue;
                            if (list.Any(b => string.Equals(b.Exe, exe, StringComparison.OrdinalIgnoreCase) || b.Name == name)) continue;
                            list.Add(new BrowserInfo { Name = name, Exe = exe });
                        }
            }
            return list.OrderBy(b => b.Name).ToList();
        }

        public static BrowserInfo Find(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            // Реестр может вернуть то же имя браузера в другом регистре — сравниваем без учёта регистра.
            return Installed().FirstOrDefault(b => string.Equals(b.Name, name, StringComparison.OrdinalIgnoreCase));
        }

        static string ExeFromCommand(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return null;
            cmd = cmd.Trim();
            if (cmd.StartsWith("\"")) { int e = cmd.IndexOf('"', 1); return e > 1 ? cmd.Substring(1, e - 1) : null; }
            int x = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return x > 0 ? cmd.Substring(0, x + 4) : cmd;
        }
    }
}

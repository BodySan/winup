using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace WinUp
{
    // Программа из каталога winget в «Моём наборе» (apps.json): ставится на новом ПК без установщика в apps\.
    public class WingetPackage
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }

    // Строка таблицы winget (search / upgrade / list).
    public class WingetRow
    {
        public string Name, Id, Version, Available, Source, Match;
    }

    // Работа с winget (менеджер пакетов Windows, «Установщик приложений» из Microsoft Store).
    // Вывод читается из перенаправленного потока: таблицы полной ширины, без обрезки ID.
    static class Winget
    {
        public const string GetUrl = "https://aka.ms/getwinget";
        const string Common = " --source winget --accept-source-agreements --disable-interactivity";

        // winget — псевдоним приложения в %LOCALAPPDATA%\Microsoft\WindowsApps (у процесса с правами
        // администратора этой папки может не быть в PATH, поэтому путь — явный).
        public static string Exe()
        {
            var alias = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "winget.exe");
            return File.Exists(alias) ? alias : "winget";
        }

        public sealed class Result
        {
            public int ExitCode;
            public string Output = "";
            public string StartError;   // winget не запустился (нет на ПК)
            public bool Cancelled;
        }

        // Запуск winget. onLine — строки вывода по мере появления (для журнала). Отмена убивает дерево процессов.
        public static Result Run(string args, CancellationToken ct, Action<string> onLine = null, Action<int> started = null)
        {
            var r = new Result();
            var sb = new StringBuilder();
            var psi = new ProcessStartInfo(Exe(), args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            };
            Process p;
            try { p = Process.Start(psi); }
            catch (Exception ex) { r.StartError = ex.Message; return r; }
            using (p)
            {
                if (started != null) try { started(p.Id); } catch { }
                DataReceivedEventHandler h = (s, e) =>
                {
                    if (e.Data == null) return;
                    lock (sb) sb.AppendLine(e.Data);
                    var line = Clean(e.Data);
                    if (onLine != null && line.Length > 0) onLine(line);
                };
                p.OutputDataReceived += h; p.ErrorDataReceived += h;
                p.BeginOutputReadLine(); p.BeginErrorReadLine();
                while (!p.WaitForExit(200))
                {
                    if (ct.IsCancellationRequested) { Kill(p.Id); r.Cancelled = true; break; }
                }
                try { p.WaitForExit(); } catch { }
                r.ExitCode = r.Cancelled ? -1 : p.ExitCode;
            }
            lock (sb) r.Output = sb.ToString();
            return r;
        }

        public static void Kill(int pid)
        {
            try
            {
                using (var tk = Process.Start(new ProcessStartInfo("taskkill", "/T /F /PID " + pid) { UseShellExecute = false, CreateNoWindow = true }))
                    tk.WaitForExit(10000);
            }
            catch { }
        }

        // Строка вывода без индикаторов прогресса: winget перерисовывает строку через \r и рисует полосы из блоков.
        public static string Clean(string line)
        {
            if (line == null) return "";
            line = line.TrimEnd('\r', '\n'); // конец строки — не перерисовка прогресса
            int cr = line.LastIndexOf('\r');
            if (cr >= 0) line = line.Substring(cr + 1);
            var t = line.Trim();
            if (t.Length == 0) return "";
            if (t.All(c => c == '-' || c == '\\' || c == '|' || c == '/' || char.IsWhiteSpace(c))) return ""; // крутилка
            if (t.Any(c => c == '█' || c == '▒')) return ""; // полоса загрузки
            return t;
        }

        // Версия winget или null, если его нет.
        public static string Version()
        {
            var r = Run("--version", CancellationToken.None);
            if (r.StartError != null || r.ExitCode != 0) return null;
            var v = r.Output.Split('\n').Select(Clean).FirstOrDefault(x => x.Length > 0);
            return string.IsNullOrEmpty(v) ? null : v;
        }

        public static string SearchArgs(string query) { return "search " + Quote(query) + Common; }
        public static string UpgradesArgs() { return "upgrade" + Common; }
        public static string ListArgs() { return "list" + Common; }

        public static string ActionArgs(string action, string id, bool silent)
        {
            return action + " --id " + Quote(id) + " --exact" + Common + " --accept-package-agreements" + (silent ? " --silent" : " --interactive");
        }

        static string Quote(string s) { return "\"" + (s ?? "").Replace("\"", "") + "\""; }

        // Разбор таблиц вывода. Заголовок — строка над линией из «-»; начала колонок — по словам заголовка,
        // но только там, где во всех строках данных перед колонкой пробел (многословный заголовок не рвёт колонку).
        public static List<WingetRow> ParseTables(string output)
        {
            var rows = new List<WingetRow>();
            var lines = (output ?? "").Replace("\r\n", "\n").Split('\n').Select(l => { int cr = l.LastIndexOf('\r'); return cr >= 0 ? l.Substring(cr + 1) : l; }).ToArray();
            for (int i = 1; i < lines.Length; i++)
            {
                if (!IsSeparator(lines[i])) continue;
                var header = lines[i - 1];
                int end = i + 1;
                while (end < lines.Length && lines[end].Trim().Length > 0 && !IsSeparator(lines[end])) end++;
                var data = lines.Skip(i + 1).Take(end - i - 1).ToList();
                var starts = new List<int>();
                for (int c = 0; c < header.Length; c++)
                    if (header[c] != ' ' && (c == 0 || header[c - 1] == ' ')) starts.Add(c);
                starts = starts.Where(c => c == 0 || data.All(d => d.Length <= c || d[c - 1] == ' ')).ToList();
                if (starts.Count < 2) continue;
                var names = starts.Select((s, k) => Cut(header, s, k + 1 < starts.Count ? starts[k + 1] : int.MaxValue).ToLowerInvariant()).ToList();
                foreach (var d in data)
                {
                    var cells = starts.Select((s, k) => Cut(d, s, k + 1 < starts.Count ? starts[k + 1] : int.MaxValue)).ToList();
                    var row = new WingetRow { Name = cells[0], Id = cells[1] };
                    if (row.Id.Length == 0 || row.Id.Contains(" ")) continue; // итоговая строка «N upgrades available.» и т.п.
                    for (int k = 2; k < cells.Count; k++)
                    {
                        var n = names[k];
                        if (n.StartsWith("version") || n.StartsWith("верс")) row.Version = cells[k];
                        else if (n.StartsWith("avail") || n.StartsWith("доступ")) row.Available = cells[k];
                        else if (n.StartsWith("source") || n.StartsWith("источ")) row.Source = cells[k];
                        else if (n.StartsWith("match") || n.StartsWith("совпад")) row.Match = cells[k];
                    }
                    rows.Add(row);
                }
                i = end - 1;
            }
            return rows;
        }

        static bool IsSeparator(string l) { var t = l.Trim(); return t.Length >= 10 && t.All(c => c == '-'); }

        static string Cut(string s, int from, int to)
        {
            if (from >= s.Length) return "";
            return s.Substring(from, Math.Min(s.Length, to) - from).Trim();
        }

        // Итог по коду выхода winget (коды APPINSTALLER_CLI_ERROR_* из документации winget).
        public static string Describe(int code, string output, string action, out bool ok)
        {
            ok = false;
            switch (unchecked((uint)code))
            {
                case 0: ok = true; return "готово";
                case 0x8A15002B: ok = true; return action == "install" ? "уже установлена, новее нет" : "обновлений нет"; // установка уже стоящей программы winget сводит к обновлению
                case 0x8A150061: ok = true; return "уже установлено";
                case 0x8A150109: ok = true; return "готово, нужна перезагрузка";
                case 0x8A150014: return "пакет не найден в каталоге";
                case 0x8A150010: return "нет установленной программы для обновления";
                case 0x8A15010B: return "отменено (установщик закрыли или отказали в правах)";
            }
            // Последняя содержательная строка вывода — обычно причина на языке winget.
            var last = (output ?? "").Split('\n').Select(Clean).LastOrDefault(l => l.Length > 3);
            return "ошибка 0x" + unchecked((uint)code).ToString("X8") + (string.IsNullOrEmpty(last) ? "" : ": " + last);
        }
    }

    // Очередь установки/обновления через winget. Как InstallForm: отдельный процесс с правами администратора
    // (один UAC на пачку), «Прервать текущую», закрытие окна отменяет остаток очереди.
    class WingetForm : Form
    {
        readonly List<string> ids;
        readonly string action;   // "install" | "upgrade"
        readonly bool silent;
        readonly ListView lv = new ListView { View = View.Details, FullRowSelect = true, Dock = DockStyle.Fill };
        readonly TextBox log = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Bottom, Height = 170 };
        readonly Button skip = new Button { Text = "Прервать текущую", AutoSize = true, Enabled = false };
        readonly Button close = new Button { Text = "Закрыть", AutoSize = true, Enabled = false };
        CancellationTokenSource current;
        volatile int currentPid;  // winget в работе: при закрытии окна убиваем его сразу, а не из фоновой задачи
        bool cancelled;

        public WingetForm(List<string> ids, string action, bool silent)
        {
            this.ids = ids; this.action = action; this.silent = silent;
            Text = "WinUp — " + (action == "upgrade" ? "обновление" : "установка") + " из каталога winget" + (Win.IsAdmin() ? "" : " (без прав администратора)");
            Font = new Font("Segoe UI", 9f);
            Size = new Size(760, 540);
            StartPosition = FormStartPosition.CenterScreen;
            lv.Columns.Add("Программа (ID)", 330); lv.Columns.Add("Действие", 100); lv.Columns.Add("Статус", 290);
            foreach (var id in ids)
            {
                var it = new ListViewItem(id);
                it.SubItems.Add(action == "upgrade" ? "обновить" : "установить");
                it.SubItems.Add("в очереди");
                lv.Items.Add(it);
            }
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4) };
            bar.Controls.Add(skip); bar.Controls.Add(close);
            Controls.Add(lv); Controls.Add(log); Controls.Add(bar);
            skip.Click += (s, e) => { var c = current; if (c != null) c.Cancel(); };
            close.Click += (s, e) => Close();
            // Закрытие окна = отмена очереди. Убиваем winget синхронно: после закрытия процесс WinUp завершается,
            // фоновая задача не успела бы остановить winget, и он доустанавливал программу сам (так переустановился Firefox).
            FormClosing += (s, e) => { cancelled = true; var c = current; if (c != null) c.Cancel(); var pid = currentPid; if (pid != 0) Winget.Kill(pid); };
            Shown += async (s, e) => await RunAll();
        }

        void Log(string m)
        {
            if (IsDisposed || log.IsDisposed) return;
            if (InvokeRequired) { try { BeginInvoke((Action)(() => Log(m))); } catch { } return; }
            log.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + m + "\r\n");
        }

        async System.Threading.Tasks.Task RunAll()
        {
            skip.Enabled = true;
            int ok = 0;
            for (int i = 0; i < ids.Count && !cancelled; i++)
            {
                var id = ids[i]; var row = lv.Items[i];
                row.SubItems[2].Text = (action == "upgrade" ? "обновляется..." : "устанавливается...") + " (загрузка может занять время)";
                row.EnsureVisible();
                Log(id + ": winget " + action + (silent ? " (тихо)" : " (с окнами установщика)"));
                current = new CancellationTokenSource();
                var ct = current.Token;
                var r = await System.Threading.Tasks.Task.Run(() => Winget.Run(Winget.ActionArgs(action, id, silent), ct, line => Log("  " + line), pid => currentPid = pid));
                current = null; currentPid = 0;
                if (IsDisposed) return;
                if (r.StartError != null) { row.SubItems[2].Text = "winget не запустился"; Log(id + ": " + r.StartError); break; }
                if (r.Cancelled) { row.SubItems[2].Text = "прервано (результат не гарантирован)"; Log(id + ": прервано пользователем"); continue; }
                bool good;
                row.SubItems[2].Text = Winget.Describe(r.ExitCode, r.Output, action, out good);
                if (good) ok++;
                Log(id + ": код " + r.ExitCode + " — " + row.SubItems[2].Text);
            }
            if (IsDisposed) return;
            Log("Готово: успешно " + ok + " из " + ids.Count + ".");
            skip.Enabled = false; close.Enabled = true;
        }
    }
}

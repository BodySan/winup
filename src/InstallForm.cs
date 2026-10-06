using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace WinUp
{
    // Очередь установки. Запускается в отдельном процессе с правами администратора (один UAC на пачку).
    class InstallForm : Form
    {
        readonly List<AppItem> items;
        readonly bool silent;
        readonly ListView lv = new ListView { View = View.Details, FullRowSelect = true, Dock = DockStyle.Fill };
        readonly TextBox log = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Bottom, Height = 150 };
        readonly Button skip = new Button { Text = "Прервать текущую", AutoSize = true, Enabled = false };
        readonly Button close = new Button { Text = "Закрыть", AutoSize = true, Enabled = false };
        Process current;
        int currentPid;  // pid текущего установщика: фиксируем сразу после запуска (после завершения процесса Process может выбросить)
        bool aborted;    // «Прервать текущую»: прервать ожидание текущего установщика, очередь продолжается
        bool cancelled;  // закрытие окна: отменить всю очередь

        public InstallForm(List<AppItem> items, bool silent)
        {
            this.items = items; this.silent = silent;
            Text = "WinUp — установка" + (Win.IsAdmin() ? "" : " (без прав администратора)");
            Font = new Font("Segoe UI", 9f);
            Size = new Size(720, 520);
            StartPosition = FormStartPosition.CenterScreen;

            lv.Columns.Add("Программа", 300); lv.Columns.Add("Режим", 110); lv.Columns.Add("Статус", 260);
            foreach (var a in items)
            {
                var it = new ListViewItem(a.Name);
                it.SubItems.Add(silent && !string.IsNullOrEmpty(a.Args) ? "тихо" : "вручную");
                it.SubItems.Add("в очереди");
                lv.Items.Add(it);
            }
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4) };
            bar.Controls.Add(skip); bar.Controls.Add(close);
            Controls.Add(lv); Controls.Add(log); Controls.Add(bar);

            skip.Click += (s, e) => { aborted = true; KillCurrent(); };
            close.Click += (s, e) => Close();
            FormClosing += (s, e) => { cancelled = true; KillCurrent(); }; // закрытие окна = отмена установки
            Shown += (s, e) => Run();
        }

        void Log(string m)
        {
            if (log.IsDisposed) return; // окно уже закрыто — лог не пишем
            log.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + m + "\r\n");
        }

        // Прерывание текущего установщика: Kill() срубает только прямой процесс, а msiexec плодит служебный
        // msiexec, NSIS/Inno — распаковщиков, поэтому убиваем дерево через taskkill /T. Не помог — запасной Kill().
        void KillCurrent()
        {
            var p = current;
            if (p == null) return;
            try
            {
                if (p.HasExited) return; // уже завершился сам — убивать нечего
                int pid = currentPid; // захвачен до ожидания: после завершения процесса Process может выбросить
                if (pid != 0)
                {
                    try
                    {
                        using (var tk = Process.Start(new ProcessStartInfo("taskkill", "/T /F /PID " + pid) { UseShellExecute = false, CreateNoWindow = true }))
                            tk.WaitForExit(10000);
                    }
                    catch { }
                }
                if (!p.HasExited) p.Kill();
            }
            catch { }
        }

        void Run()
        {
            skip.Enabled = true;
            int ok = 0;
            for (int i = 0; i < items.Count; i++)
            {
                var a = items[i]; var row = lv.Items[i];
                var path = Paths.Full(a.File);
                if (!File.Exists(path)) { row.SubItems[2].Text = "файл не найден"; Log(a.Name + ": файл не найден — " + path); continue; }
                bool quiet = silent && !string.IsNullOrEmpty(a.Args);
                row.SubItems[2].Text = "устанавливается..."; row.EnsureVisible();
                Log(a.Name + ": запуск " + (quiet ? "тихо (" + a.Args + ")" : "вручную"));
                try
                {
                    var psi = path.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
                        ? new ProcessStartInfo("msiexec.exe", "/i \"" + path + "\"" + (quiet ? " " + a.Args : ""))
                        : new ProcessStartInfo(path, quiet ? a.Args : "");
                    psi.UseShellExecute = true;
                    psi.WorkingDirectory = Path.GetDirectoryName(path);
                    using (var p = Process.Start(psi)) // Process держит хэндл — освобождаем (Dispose)
                    {
                        current = p;
                        currentPid = 0;
                        try { currentPid = p.Id; } catch { } // pid нужен для taskkill
                        aborted = false; // флаг «Прервать текущую» действует на один установщик
                        // Ждём порциями и прокачиваем очередь сообщений: зависший установщик
                        // (тихий режим ждёт ввода, веб-загрузчик без сети) не вешает окно намертво.
                        while (!p.WaitForExit(500)) { Application.DoEvents(); if (aborted || cancelled) break; }
                        if (aborted || cancelled)
                        {
                            row.SubItems[2].Text = "прервано (результат установки не гарантирован)";
                            Log(a.Name + ": прервано пользователем");
                        }
                        else
                        {
                            int code = p.ExitCode;
                            bool good = code == 0 || code == 3010 || code == 1641;
                            if (good) ok++;
                            row.SubItems[2].Text = good ? (code == 0 ? "готово" : "готово, нужна перезагрузка") : "ошибка, код " + code;
                            Log(a.Name + ": код выхода " + code);
                        }
                    }
                }
                catch (Exception ex)
                {
                    row.SubItems[2].Text = "не запустился";
                    Log(a.Name + ": " + ex.Message);
                }
                current = null; currentPid = 0;
                if (cancelled) break; // окно закрыли — остальную очередь не запускаем
            }
            Log("Готово: успешно " + ok + " из " + items.Count + ".");
            skip.Enabled = false; close.Enabled = true;
        }
    }
}

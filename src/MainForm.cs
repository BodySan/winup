using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinUp
{
    partial class MainForm : Form
    {
    readonly AppStore store;
    bool BaseExists() { return KdbxStore.Exists || Vault.LegacyExists; }
    KdbxStore vault;
    KdbxStore.PinSession pin;              // быстрый вход: живёт только в памяти работающего приложения
    DateTime? lockedAt;                    // когда заблокирована — PIN гаснет после долгого простоя
    public const int PinSessionMinutes = 10;
    bool appsTampered;                 // apps.json изменён вне WinUp с прошлого запуска
    string appsTamperHash;
    bool appsUntrusted;                // изменённый список не принят: запуск — только после подтверждения
    // Расширение браузера: сервер канала моста (запросы значка в полях входа на сайтах).
    readonly BrowserServer browserServer = new BrowserServer();
    TrayIcon tray;                       // значок в области уведомлений: состояние базы и быстрая блокировка
    FormWindowState trayRestoreState = FormWindowState.Normal;
    ToolStripMenuItem lockMenu;          // «Заблокировать» справа в строке меню
    // Доступ для сервера канала (читается только в потоке интерфейса через Invoke).
    // Имя не «Vault»: оно затмевало бы статический класс Vault (старая база, миграция).
    internal KdbxStore VaultNow { get { return vault; } }
    internal int BrowserGeneration { get { return lockGen; } }
    // Запрос расширения «Открыть базу»: окно ввода пароля — только если база закрыта и другое окно WinUp
    // (ввод пароля, подтверждение) уже не открыто: повторные запросы не громоздят окна друг на друга.
    internal void UnlockBrowser()
    {
        ShowFromTray();
        if (vault != null || Application.OpenForms.OfType<Dlg>().Any()) return;
        SelectTab("Пароли");
        Unlock();
    }
    // Уведомление о каждой выдаче пароля расширению (FillToast); переключатель — в окне «Расширение для браузера».
    internal static bool FillNotifyEnabled = true;
    internal void SetFillNotify(bool on)
    {
        FillNotifyEnabled = store.Settings.FillNotify = on;
        SaveApps();
        PwLog(on ? "Расширение: уведомление о каждой вставке пароля включено." : "Расширение: уведомление о вставке пароля выключено.");
    }
    internal void NotifyFill(string entry, string site)
    {
        if (!FillNotifyEnabled) return;
        try
        {
            FillToast.Notify(entry, site, delegate
            {
                if (vault == null) return;
                LockVault();
                PwLog("Заблокировано кнопкой в уведомлении о вставке пароля в браузере.");
            });
        }
        catch (Exception ex) { PwLog("Уведомление о вставке не показано: " + ex.GetType().Name + ": " + ex.Message); }
    }

        readonly TabControl tabs = new TabControl { Dock = DockStyle.Fill };
        readonly ListView instList = NewList(true), portList = NewList(false), pwList = NewList(false), linkList = NewList(false);
        readonly TextBox instDesc = DescBox(), portDesc = DescBox(), linkDesc = DescBox();
        readonly CheckBox silentBox = new CheckBox { Text = "Тихо, без подтверждений", Checked = true, AutoSize = true, Margin = new Padding(8, 8, 3, 3) };
        readonly Label status = new Label { Dock = DockStyle.Bottom, Height = 22, AutoEllipsis = true, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(6, 0, 0, 0) };
        readonly TextBox pwLog = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Bottom, Height = 110 };
        readonly Panel lockedPanel = new Panel { Dock = DockStyle.Fill }, openPanel = new Panel { Dock = DockStyle.Fill };
        readonly Label lockedText = new Label { AutoSize = true, MaximumSize = new Size(640, 0), Location = new Point(20, 20) };
        readonly Button unlockBtn = new Button { AutoSize = true, Location = new Point(20, 90) };
        readonly System.Windows.Forms.Timer lockTimer = new System.Windows.Forms.Timer { Interval = 10000 };
        bool busyLogin;
        bool cloudNoted;                   // предупреждение «папка в облаке» — раз за запуск
        // Плашка «давно не проверяли обновления» над вкладками (см. Reminder).
        readonly Panel updBanner = new Panel { Dock = DockStyle.Top, Height = 36, Visible = false, BackColor = Color.FromArgb(255, 244, 206) };
        readonly Label updText = new Label { AutoSize = true, Margin = new Padding(6, 9, 6, 3) };
        DateTime updShownDay;

        public MainForm(AppStore store, bool refreshBrowserConnection = true)
        {
            this.store = store;
            Win.CaptureProtection = store.Settings.HideFromCapture; // до создания окон: они защищаются при появлении
            FillNotifyEnabled = store.Settings.FillNotify;
            Text = "WinUp — " + Paths.Root;
            Font = new Font("Segoe UI", 9f);
            Icon = AppIcons.Open;
            Size = new Size(Math.Min(1080,Screen.PrimaryScreen.WorkingArea.Width-40),Math.Min(760,Screen.PrimaryScreen.WorkingArea.Height-40));
            MinimumSize = new Size(700, 550);
            StartPosition = FormStartPosition.CenterScreen;

            Controls.Add(tabs);
            Controls.Add(status);
            BuildUpdateBanner(); // до меню: верхние панели раскладываются от последней добавленной, меню остаётся выше плашки
            BuildMenu();
            tray = new TrayIcon(ShowFromTray, delegate { LockVaultCore(true); PwLog("База паролей, 2FA и ключей доступа заблокирована; файловое хранилище не закрывалось."); },
                                delegate { ShowFromTray(); SelectTab("Пароли"); if (vault == null) Unlock(); }, Close,CloseFileVaultSafely,LockVault);
            BuildPasswordTab();
            BuildCodesTab();
            BuildPasskeyTab();
            BuildFileVaultTab();
            BuildPortableTab();
            BuildWingetTab();
            BuildInstallTab();
            BuildLinksTab();
            Appearance.Apply(this);
            Appearance.MainStatus(status);
            RefreshApps();
            ShowLocked();
            // Файл базы мог появиться или исчезнуть, пока окно открыто (восстановили vault-*.kdbx из резерва):
            // при каждом заходе на вкладку замок показывает актуальную кнопку «Открыть» / «Создать базу».
            tabs.SelectedIndexChanged += (s, e) => { if (vault == null) ShowLocked(); };

            // Остатки аварийно прерванного экспорта: открытый XML с паролями не должен
            // переезжать вместе с папкой на флешке; незавершённые .tmp атомарной записи
            // тоже убираем (ревью R-5).
            try
            {
                foreach (var f in Directory.GetFiles(Paths.Data, "export-*.xml").Where(f => System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(f), @"^export-[0-9a-fA-F]{32}\.xml$"))) { string error; Secure.WipeFile(f, out error); }
                foreach (var name in new[] { "vault.kdbx", "recovery.kdbx", "tab.dat", "vault.dat", "apps.json" })
                    foreach (var f in Paths.AtomicRemnants(Path.Combine(Paths.Data, name))) { string error; Secure.WipeFile(f, out error); }
            }
            catch { }

            // Список программ (apps.json) не имеет криптографической защиты — следим за его изменением
            // «доверенным при первом использовании»: свои записи WinUp обновляет сам, чужие заметны.
            // Сверка сделана в AppStore.Load до любой записи списка.
            if (AppStore.ChangedOutside != null) { appsTampered = true; appsTamperHash = AppStore.ChangedOutside; }

            lockTimer.Tick += (s, e) =>
            {
                int mins = Math.Max(1, store.Settings.AutoLockMinutes);
                if ((vault != null || unlockBusy) && Win.Idle().TotalMinutes >= mins)
                {
                    bool keepProject=fileVault!=null && filePreferences.ProjectMode && Win.Idle().TotalMinutes<filePreferences.ProjectIdleMinutes;
                    LockVaultCore(keepProject);
                    PwLog("Заблокировано автоматически после " + mins + " мин простоя.");
                }
                if(vault==null&&fileVault!=null&&!fileBusy&&Win.Idle().TotalMinutes>=
                    (filePreferences.ProjectMode ? filePreferences.ProjectIdleMinutes : mins)) {
                    try {
                        var busy=fileVault.BusyFiles();
                        if(busy.Length==0)TryCloseFileVault();
                        else fileState.Text="Пароли закрыты. Диск проекта открыт: сохраните и закройте занятые файлы перед отключением.";
                    } catch(IOException) {fileState.Text="Автоматическое отключение отложено: не удалось проверить занятые файлы. Закройте хранилище вручную.";}
                      catch(UnauthorizedAccessException) {fileState.Text="Автоматическое отключение отложено: нет доступа к части файлов. Закройте хранилище вручную.";}
                }
                // WinUp может неделями стоять открытым: срок напоминания перепроверяется раз в сутки.
                if (updShownDay != DateTime.Today) RefreshUpdateBanner();
            };
            lockTimer.Start();

            // Версия и источник крипто-ядра — в журнал при каждом запуске (вшитое или обновлённое из data\core).
            PwLog("Крипто-ядро: KeePassLib " + KdbxStore.LibVersion() + " (" + CoreLoader.Source + ").");
            if (!string.IsNullOrEmpty(CoreLoader.Note)) PwLog(CoreLoader.Note);

            // Расширение браузера: обновить путь exe/версию папки, если подключено; принять канал моста.
            if (refreshBrowserConnection) try { BrowserSetup.RefreshIfNeeded(); } catch { }
            if (BrowserSetup.RestoredFiles > 0)
                PwLog("Расширение браузера: файлы в " + BrowserSetup.BrowserDir + " отличались от встроенных в WinUp — восстановлены. " +
                      "Если вы их не меняли, проверьте ПК антивирусом. Перезапустите браузер, чтобы он загрузил исправные файлы.");
            if (BrowserSetup.UpdatedFrom != null)
                PwLog("Расширение браузера обновлено: " + BrowserSetup.UpdatedFrom + " → " + BrowserSetup.Version +
                      ". Перезапустите браузер, чтобы он загрузил новую версию.");
            browserServer.Start(this);
            Shown += async (s, e) =>
            {
                if (appsTampered)
                {
                    appsTampered = false;
                    if (MessageBox.Show(this, "Список программ (apps.json) был изменён вне WinUp.\n\n" +
                            "Если вы не редактировали его сами — проверьте записи на вкладках «Установка» и «Запуск» " +
                            "(особенно параметры запуска) перед тем, как что-то запускать.\n\nПринять новый список?",
                            "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                        try { Integrity.SetApps(appsTamperHash); } catch { }
                    else
                    {
                        // Не принят — каждый запуск из списка показывает точный путь и параметры и ждёт подтверждения.
                        appsUntrusted = true;
                        SetStatus("Список программ изменён вне WinUp и не принят: перед каждым запуском WinUp покажет, что именно запускается.");
                    }
                }
                if (!store.Settings.WizardDone && store.Apps.Count == 0 && !BaseExists())
                {
                    // Свежая копия: ядро в ней новое — отсчёт напоминания начинается сегодня, плашка не мешает мастеру.
                    Reminder.StartCountdownIfNew();
                    await RunWizard();
                    return;
                }
                RefreshUpdateBanner();
                if (!store.Settings.WizardDone) { store.Settings.WizardDone = true; SaveApps(); }
                await ScanNew(true);
            };
            FormClosed += (s, e) =>
            {
                var closingTray=tray;tray=null;if(closingTray!=null)closingTray.Dispose();
                browserServer.Stop();
                FillToast.CloseAll();
                CloseFileVault();
                if (vault != null) vault.Lock();
                if (pin != null) { pin.Clear(); pin = null; }
                SecureClip.ClearNow();
            };
        }

        static ListView NewList(bool checks)
        {
            return new ListView { View = View.Details, FullRowSelect = true, CheckBoxes = checks, Dock = DockStyle.Fill, HideSelection = false, MultiSelect = true };
        }

        static TextBox DescBox()
        {
            return new TextBox { Multiline = true, ReadOnly = true, Dock = DockStyle.Bottom, Height = 58, ScrollBars = ScrollBars.Vertical, TabStop = false };
        }

        // Внизу вкладки — полное описание выбранной строки.
        static void BindDesc(ListView lv, TextBox box, Func<object, string> text)
        {
            lv.SelectedIndexChanged += (s, e) => box.Text = lv.SelectedItems.Count > 0 ? text(lv.SelectedItems[0].Tag) : "";
        }

        static FlowLayoutPanel Bar() { return new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(3) }; }

        static Button Btn(FlowLayoutPanel bar, string text, EventHandler click)
        {
            var b = new Button { Text = text, AutoSize = true };
            b.Click += click;
            bar.Controls.Add(b);
            return b;
        }

        void SetStatus(string s) { status.Text = s; }
        internal string PreferredBrowser {get {return store.Settings.Browser ?? "";}}

        static string AppDesc(AppItem a)
        {
            var d = string.IsNullOrEmpty(a.Description) ? "Описания нет — добавьте в «Изменить...»." : a.Description;
            return a.Name + ": " + d + (string.IsNullOrEmpty(a.Note) ? "" : "\r\nПримечание: " + a.Note) + "\r\nФайл: " + a.File;
        }

        // ---------------- Скачать ----------------

        void BuildLinksTab()
        {
            var page = new TabPage("Скачать");
            linkList.Columns.Add("Программа", 200); linkList.Columns.Add("Описание", 420); linkList.Columns.Add("Сайт", 260);
            var bar = Bar();
            Btn(bar, "Открыть сайт", (s, e) => OpenLink());
            Btn(bar, "Добавить...", (s, e) =>
            {
                var l = new LinkItem { Id = AppStore.NewId(), Url = "https://" };
                using (var d = new LinkDialog(l)) if (d.ShowDialog(this) == DialogResult.OK) { store.Links.Add(l); SaveApps(); }
            });
            Btn(bar, "Изменить...", (s, e) =>
            {
                var l = SelectedLink();
                if (l == null) return;
                using (var d = new LinkDialog(l)) if (d.ShowDialog(this) == DialogResult.OK) SaveApps();
            });
            Btn(bar, "Удалить", (s, e) =>
            {
                var l = SelectedLink();
                if (l == null || MessageBox.Show(this, "Удалить ссылку «" + l.Name + "»?", "WinUp", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                store.Links.Remove(l); SaveApps();
            });
            linkList.DoubleClick += (s, e) => OpenLink();
            BindDesc(linkList, linkDesc, t => { var l = (LinkItem)t; return l.Name + ": " + (l.Description ?? "") + "\r\nСайт: " + l.Url; });
            page.Controls.Add(linkList); page.Controls.Add(linkDesc); page.Controls.Add(bar);
            ArrangeActions(page,new[]{bar},new ActionGroup("Скачать",Actions(bar,"Открыть сайт")),new ActionGroup("Список",Actions(bar,"Добавить...","Изменить...","Удалить")));
            tabs.TabPages.Add(page);
        }

        LinkItem SelectedLink() { return linkList.SelectedItems.Count > 0 ? (LinkItem)linkList.SelectedItems[0].Tag : null; }

        void OpenLink()
        {
            var l = SelectedLink();
            if (l == null) return;
            try { Process.Start(new ProcessStartInfo(l.Url) { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show(this, l.Name + ": " + ex.Message, "WinUp"); }
        }

        // ---------------- Установка / Запуск ----------------

        void BuildInstallTab()
        {
            var page = new TabPage("Установка");
            instList.Columns.Add("Программа", 200); instList.Columns.Add("Описание", 330); instList.Columns.Add("Ключи тихой установки", 200);
            instList.Columns.Add("Примечание", 160); instList.Columns.Add("Файл", 200);
            var bar = Bar();
            Btn(bar, "Установить отмеченные", (s, e) => InstallChecked());
            bar.Controls.Add(silentBox);
            Btn(bar, "Отметить все / снять", (s, e) =>
            {
                bool on = instList.Items.Cast<ListViewItem>().Any(i => !i.Checked);
                foreach (ListViewItem i in instList.Items) i.Checked = on;
            });
            Btn(bar, "Добавить файлы...", async (s, e) => await AddFilesDialog("install"));
            Btn(bar, "Добавить папку...", async (s, e) => await AddFolderDialog());
            Btn(bar, "Найти новые в apps", async (s, e) => await ScanNew(false));
            Btn(bar, "Найти установщики на ПК...", async (s, e) => await FindInstallers());
            Btn(bar, "Изменить...", (s, e) => EditSelected(instList));
            Btn(bar, "Убрать из списка", (s, e) => RemoveSelected(instList));
            instList.DoubleClick += (s, e) => EditSelected(instList);
            BindDesc(instList, instDesc, t => AppDesc((AppItem)t));
            page.Controls.Add(instList); page.Controls.Add(instDesc); page.Controls.Add(bar);
            ArrangeActions(page,new[]{bar},
                new ActionGroup("Установка",Actions(bar,"Установить отмеченные","Тихо, без подтверждений","Отметить все / снять")),
                new ActionGroup("Добавление",Actions(bar,"Добавить файлы...","Добавить папку...","Найти новые в apps","Найти установщики на ПК...")),
                new ActionGroup("Список",Actions(bar,"Изменить...","Убрать из списка")));
            tabs.TabPages.Add(page);
        }

        void BuildPortableTab()
        {
            var page = new TabPage("Запуск");
            portList.Columns.Add("Программа", 200); portList.Columns.Add("Описание", 420); portList.Columns.Add("Файл", 250);
            var bar = Bar();
            Btn(bar, "Запустить", (s, e) => LaunchSelected());
            Btn(bar, "Добавить файлы...", async (s, e) => await AddFilesDialog("portable"));
            Btn(bar, "Изменить...", (s, e) => EditSelected(portList));
            Btn(bar, "Убрать из списка", (s, e) => RemoveSelected(portList));
            portList.DoubleClick += (s, e) => LaunchSelected();
            BindDesc(portList, portDesc, t => AppDesc((AppItem)t));
            page.Controls.Add(portList); page.Controls.Add(portDesc); page.Controls.Add(bar);
            ArrangeActions(page,new[]{bar},new ActionGroup("Запуск",Actions(bar,"Запустить")),new ActionGroup("Список",Actions(bar,"Добавить файлы...","Изменить...","Убрать из списка")));
            tabs.TabPages.Add(page);
        }

        void RefreshApps()
        {
            var checkedIds = new HashSet<string>(instList.CheckedItems.Cast<ListViewItem>().Select(i => ((AppItem)i.Tag).Id));
            var selectedApps = new HashSet<string>(instList.SelectedItems.Cast<ListViewItem>().Concat(portList.SelectedItems.Cast<ListViewItem>()).Select(i => ((AppItem)i.Tag).Id));
            var selectedLinks = new HashSet<string>(linkList.SelectedItems.Cast<ListViewItem>().Select(i => ((LinkItem)i.Tag).Id));
            instList.BeginUpdate(); portList.BeginUpdate();
            instList.Items.Clear(); portList.Items.Clear();
            foreach (var a in store.Apps.OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                bool exists = a.Exists;
                ListViewItem it;
                if (a.Kind == "portable")
                {
                    it = new ListViewItem(new[] { a.Name + (a.Admin ? "  (админ)" : ""), a.Description ?? "", a.File });
                    portList.Items.Add(it);
                }
                else
                {
                    it = new ListViewItem(new[] { a.Name, a.Description ?? "", string.IsNullOrEmpty(a.Args) ? "(вручную)" : a.Args, a.Note ?? "", a.File });
                    it.Checked = checkedIds.Contains(a.Id);
                    instList.Items.Add(it);
                }
                it.Tag = a;
                it.Selected = selectedApps.Contains(a.Id);
                if (!exists) { it.ForeColor = Color.Firebrick; it.SubItems[it.SubItems.Count - 1].Text = a.File + " (файл не найден)"; }
            }
            instList.EndUpdate(); portList.EndUpdate();
            linkList.BeginUpdate(); linkList.Items.Clear();
            foreach (var l in store.Links.OrderBy(l => l.Name, StringComparer.CurrentCultureIgnoreCase))
                linkList.Items.Add(new ListViewItem(new[] { l.Name, l.Description ?? "", l.Url }) { Tag = l, Selected = selectedLinks.Contains(l.Id) });
            linkList.EndUpdate();
            instDesc.Text = portDesc.Text = linkDesc.Text = "";
            SetStatus("Программ: " + store.Apps.Count + ". Данные: " + Paths.Data + (Backup.LastError != null ? "   ⚠ резерв: " + Backup.LastError : ""));
        }

        bool SaveApps()
        {
            try { store.Save(); RefreshApps(); return true; }
            catch (Exception ex) { MessageBox.Show(this, "Не удалось сохранить список программ:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); return false; }
        }

        async Task AddFilesDialog(string defaultKind)
        {
            using (var d = new OpenFileDialog { Multiselect = true, Filter = "Программы и установщики (*.exe;*.msi)|*.exe;*.msi|Все файлы|*.*" })
                if (d.ShowDialog(this) == DialogResult.OK) await AddFiles(d.FileNames, defaultKind);
        }

        async Task AddFolderDialog()
        {
            using (var d = new FolderBrowserDialog { Description = "Папка с установщиками (exe/msi)" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                var sub = MessageBox.Show(this, "Искать и во вложенных папках?", "WinUp", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (sub == DialogResult.Cancel) return;
                List<string> all;
                try { all = sub == DialogResult.Yes ? SafeGetFiles(d.SelectedPath) : new List<string>(Directory.GetFiles(d.SelectedPath)); }
                catch (Exception ex) { MessageBox.Show(this, "Не удалось прочитать папку:\n" + ex.Message, "WinUp"); return; }
                var data = Paths.Data;
                Func<string, bool> insideData = f => f.StartsWith(data, StringComparison.OrdinalIgnoreCase) && (f.Length == data.Length || f[data.Length] == '\\');
                var files = all
                    .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
                    .Where(f => !insideData(f)
                             && !string.Equals(f, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                if (files.Length == 0) { MessageBox.Show(this, "В папке нет exe/msi.", "WinUp"); return; }
                await AddFiles(files, "install");
            }
        }

        // Один файл на копирование (с папкой — если портативную программу забирают вместе с её файлами).
        class CopyItem
        {
            public string Src, Dst;              // полные пути: откуда, куда
            public string FolderSrc, FolderDst;  // не null — копируется вся папка
            public bool DeleteSrc;               // удалить источник после успешного копирования
        }

        // Сначала задаются все вопросы, затем копируется. Порядок важен: раньше окно отключалось
        // ещё до вопроса «Скопировать всю папку?», и диалог от отключённого окна мог спрятаться
        // за ним — выглядело как зависание (при убийстве приложения список не сохранялся).
        async Task AddFiles(string[] files, string defaultKind)
        {
            var plan = new List<CopyItem>();
            try
            {
                // Дедупликация в рамках одной пачки: одна папка — один вопрос «всю папку» и один dst,
                // один файл — один dst (два setup.exe из разных папок больше не получают одинаковый путь).
                var folderJobs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); // srcDir → dstDir
                var plannedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var plannedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var src in files)
                {
                    var full = Path.GetFullPath(src);
                    if (Paths.IsUnderRoot(full)) { plan.Add(new CopyItem { Src = full, Dst = full }); continue; }
                    var srcDir = Path.GetDirectoryName(full);
                    if (defaultKind == "portable")
                    {
                        string plannedDir;
                        if (folderJobs.TryGetValue(srcDir, out plannedDir))
                        {
                            // Папка уже забирается целиком: файл уедет вместе с ней, второй раз не спрашиваем.
                            plan.Add(new CopyItem { Src = full, Dst = Path.Combine(plannedDir, Path.GetFileName(full)), FolderSrc = srcDir, FolderDst = plannedDir });
                            continue;
                        }
                        bool deleteFolder;
                        if (AskCopyFolder(full, out deleteFolder))
                        {
                            var dstDir = Path.Combine(Paths.Apps, Path.GetFileName(srcDir));
                            for (int n = 2; Directory.Exists(dstDir) || plannedDirs.Contains(dstDir); n++) dstDir = Path.Combine(Paths.Apps, Path.GetFileName(srcDir) + " (" + n + ")");
                            folderJobs[srcDir] = dstDir; plannedDirs.Add(dstDir);
                            plan.Add(new CopyItem { Src = full, Dst = Path.Combine(dstDir, Path.GetFileName(full)), FolderSrc = srcDir, FolderDst = dstDir, DeleteSrc = deleteFolder });
                            continue;
                        }
                    }
                    Directory.CreateDirectory(Paths.Apps);
                    var dst = Path.Combine(Paths.Apps, Path.GetFileName(full));
                    // Совпадение размеров больше не считается «тем же файлом»: обновление того же
                    // размера (минорный патч) раньше молча не копировалось. Сверяем и время изменения.
                    bool clash = plannedFiles.Contains(dst);
                    if (!clash && File.Exists(dst))
                    {
                        var old = new FileInfo(dst); var cur = new FileInfo(full);
                        clash = old.Length != cur.Length || old.LastWriteTimeUtc != cur.LastWriteTimeUtc;
                    }
                    if (clash)
                    {
                        var stem = Path.GetFileNameWithoutExtension(full); var ext = Path.GetExtension(full);
                        for (int n = 2; File.Exists(dst) || plannedFiles.Contains(dst); n++) dst = Path.Combine(Paths.Apps, stem + " (" + n + ")" + ext);
                    }
                    plannedFiles.Add(dst);
                    plan.Add(new CopyItem { Src = full, Dst = dst });
                }
                int singles = plan.Count(p => p.FolderSrc == null && !Paths.IsUnderRoot(p.Src));
                if (singles > 0)
                {
                    bool del = false;
                    using (var d = new DeleteSourcesDialog(singles)) del = d.ShowDialog(this) == DialogResult.Yes;
                    foreach (var p in plan) if (p.FolderSrc == null && !Paths.IsUnderRoot(p.Src)) p.DeleteSrc = del;
                }
            }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }

            // Копирование: модальное окно с прогрессом и отменой.
            var copied = plan.Where(p => Paths.IsUnderRoot(p.Src)).ToList();
            bool cancelled = false;
            if (plan.Any(p => !Paths.IsUnderRoot(p.Src)))
            {
                using (var ui = new CopyProgressDialog())
                {
                    var handle = ui.Handle; // создать до фонового потока: репорты пойдут сразу
                    var work = Task.Run(() => CopyPlan(plan, ui));
                    ui.ShowDialog(this);
                    try { copied.AddRange(await work); }
                    catch (Exception ex) { MessageBox.Show(this, ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                    cancelled = ui.Cancelled;
                    if (ui.Errors.Count > 0)
                        MessageBox.Show(this, "Часть файлов скопировать не удалось:\n" + string.Join("\n", ui.Errors.Take(5).ToArray()),
                            "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }

            var copiedSet = new HashSet<string>(copied.Select(p => p.Dst), StringComparer.OrdinalIgnoreCase);
            int added = 0, skipped = 0, left = 0, delFailed = 0;
            foreach (var p in plan)
            {
                var rel = Paths.Rel(p.Dst);
                if (store.Apps.Any(a => string.Equals(a.File, rel, StringComparison.OrdinalIgnoreCase))) { skipped++; continue; }
                if (!copiedSet.Contains(p.Dst)) { left++; continue; }
                var item = new AppItem { Id = AppStore.NewId(), Name = Path.GetFileNameWithoutExtension(p.Dst), File = rel, Kind = defaultKind, Args = "", Note = "" };
                item.Description = Describe(p.Dst);
                if (defaultKind == "install")
                {
                    var it = item;
                    await Task.Run(() => Detect.Fill(it));
                }
                store.Apps.Add(item);
                added++;
                // Защита вдогонку: папки-контейнеры (Загрузки и т.п.) не удаляем, даже если флаг как-то установлен.
                if (p.DeleteSrc && !Recycle.IsProtectedFolder(p.FolderSrc != null ? p.FolderSrc : p.Src)
                    && !Recycle.Delete(p.FolderSrc != null ? p.FolderSrc : p.Src)) delFailed++;
            }
            SaveApps();
            SetStatus((cancelled ? "Отменено. " : "") + "Добавлено: " + added + (skipped > 0 ? ", уже были в списке: " + skipped : "") +
                      (left > 0 ? ", не скопировано: " + left : "") +
                      (delFailed > 0 ? ", НЕ удалено источников: " + delFailed + " (удалите вручную)" : "") + ". " + status.Text);
        }

        // Вопрос про папку портативной программы. Вызывается, пока окно активно, — диалог всегда виден.
        bool AskCopyFolder(string exe, out bool deleteFolder)
        {
            deleteFolder = false;
            var dir = Path.GetDirectoryName(exe);
            // Корень диска или сетевой шары «целиком» не забираем: папкой назначения стал бы сам apps\
            // (а для D:\ это копирование всего диска). Только exe.
            try { if (string.Equals(dir, Path.GetPathRoot(dir), StringComparison.OrdinalIgnoreCase)) return false; }
            catch { }
            int others = 0;
            try { others = Directory.GetFileSystemEntries(dir).Length - 1; } catch { }
            if (others <= 0) return false;
            // Для Загрузок, Рабочего стола и других папок-контейнеров галочку удаления не предлагаем.
            using (var d = new FolderCopyDialog(Path.GetFileName(exe), Path.GetFileName(dir), others, !Recycle.IsProtectedFolder(dir)))
            {
                bool whole = d.ShowDialog(this) == DialogResult.OK;
                deleteFolder = whole && d.DeleteFolder;
                return whole;
            }
        }

        // Копирование по плану: прогресс и отмена, вернутся успешные. Работает в пуле потоков.
        // Ошибка одного файла (нет доступа, файл занят) не прерывает остальные — раньше весь
        // остаток пачки молча не копировался.
        static List<CopyItem> CopyPlan(List<CopyItem> plan, CopyProgressDialog ui)
        {
            var done = new List<CopyItem>();
            var external = plan.Where(p => !Paths.IsUnderRoot(p.Src)).ToList();
            int total = 0, pos = 0;
            foreach (var p in external)
                total += p.FolderSrc != null ? CountFiles(p.FolderSrc) : 1;
            string activeDst = null; // не null только пока файл в процессе копирования
            try
            {
                foreach (var p in external)
                {
                    ui.Token.ThrowIfCancellationRequested();
                    if (p.FolderSrc == null)
                    {
                        try
                        {
                            ui.Report("Копирую " + Path.GetFileName(p.Src) + " ...", pos, total);
                            activeDst = p.Dst;
                            CopyFileProgress(p.Src, p.Dst, (d, t) => ui.Report(Path.GetFileName(p.Src) + ": " + Mb(d) + " из " + Mb(t), pos, total), ui.Token);
                            pos++; done.Add(p); activeDst = null;
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception ex) { pos++; PartialCleanup(ref activeDst); ui.Errors.Add(Path.GetFileName(p.Src) + ": " + ex.Message); }
                    }
                    else
                    {
                        string[] files;
                        try { files = Directory.GetFiles(p.FolderSrc, "*", SearchOption.AllDirectories); }
                        catch (Exception ex) { ui.Errors.Add("Папка " + Path.GetFileName(p.FolderSrc) + ": " + ex.Message); continue; }
                        bool all = true;
                        foreach (var f in files)
                        {
                            try
                            {
                                ui.Token.ThrowIfCancellationRequested();
                                var dstF = f.Replace(p.FolderSrc, p.FolderDst);
                                Directory.CreateDirectory(Path.GetDirectoryName(dstF));
                                ui.Report("Папка «" + Path.GetFileName(p.FolderSrc) + "»: " + Path.GetFileName(f) + " ...", pos, total);
                                activeDst = dstF;
                                CopyFileProgress(f, dstF, (d, t) => ui.Report(Path.GetFileName(f) + ": " + Mb(d) + " из " + Mb(t), pos, total), ui.Token);
                                pos++; activeDst = null;
                            }
                            catch (OperationCanceledException) { throw; }
                            catch (Exception ex) { pos++; PartialCleanup(ref activeDst); ui.Errors.Add(Path.GetFileName(f) + ": " + ex.Message); all = false; }
                        }
                        // Папка считается скопированной только целиком: при ошибке хоть одного
                        // файла запись не добавляем и источник не удаляем.
                        if (all) done.Add(p);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                ui.Cancelled = true;
                // Недокопированное не оставляем: текущий (незавершённый) файл удаляем, папки — целиком.
                PartialCleanup(ref activeDst);
                foreach (var p in external)
                    if (p.FolderSrc != null && !done.Contains(p))
                        try { Directory.Delete(p.FolderDst, true); } catch { }
            }
            catch (Exception ex) { ui.Errors.Add(ex.Message); }
            finally { ui.Done(); }
            return done;
        }

        // Частично записанный файл не оставляем: пустой/обрезанный dst только мешает.
        static void PartialCleanup(ref string activeDst)
        {
            if (activeDst == null) return;
            try { File.Delete(activeDst); } catch { }
            activeDst = null;
        }

        static int CountFiles(string dir)
        {
            try { return Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Length; }
            catch { return 1; }
        }

        // Обход папок без падения на недоступных каталогах и без захода в reparse-точки
        // (junction на C:\ не утащит перечисление на весь диск).
        static List<string> SafeGetFiles(string dir)
        {
            var list = new List<string>();
            var stack = new Stack<string>();
            stack.Push(dir);
            while (stack.Count > 0)
            {
                var d = stack.Pop();
                string[] fs = null, ds = null;
                try { fs = Directory.GetFiles(d); } catch { }
                if (fs != null) list.AddRange(fs);
                try { ds = Directory.GetDirectories(d); } catch { }
                if (ds == null) continue;
                foreach (var sd in ds)
                    try { if ((File.GetAttributes(sd) & FileAttributes.ReparsePoint) == 0) stack.Push(sd); }
                    catch { }
            }
            return list;
        }

        static string Mb(long b)
        {
            return b >= 1024 * 1024 ? (b / 1024.0 / 1024.0).ToString("0.#") + " МБ" : (b / 1024) + " КБ";
        }

        // Копирование кусочками по 1 МБ: и байты видны в прогрессе, и большой файл можно отменить.
        static void CopyFileProgress(string from, string to, Action<long, long> report, CancellationToken ct)
        {
            if (File.Exists(to)) return; // такой же файл уже лежит (совпадение размеров проверено при планировании)
            using (var src = File.OpenRead(from))
            using (var dst = File.Create(to))
            {
                var buf = new byte[1024 * 1024];
                long total = src.Length, copied = 0;
                int n;
                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    dst.Write(buf, 0, n);
                    copied += n;
                    report(copied, total);
                }
            }
        }

        static AppItem Selected(ListView lv)
        {
            return lv.SelectedItems.Count > 0 ? (AppItem)lv.SelectedItems[0].Tag : null;
        }

        void EditSelected(ListView lv)
        {
            var a = Selected(lv);
            if (a == null) return;
            using (var d = new AppDialog(a))
                if (d.ShowDialog(this) == DialogResult.OK) SaveApps();
        }

        void RemoveSelected(ListView lv)
        {
            var sel = lv.SelectedItems.Cast<ListViewItem>().Select(i => (AppItem)i.Tag).ToList();
            if (sel.Count == 0) return;
            if (MessageBox.Show(this, "Убрать из списка: " + string.Join(", ", sel.Select(a => a.Name)) + "?\nСами файлы не удаляются.",
                    "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            foreach (var a in sel) store.Apps.Remove(a);
            SaveApps();
        }

        void LaunchSelected()
        {
            var a = Selected(portList);
            if (a == null) return;
            if (!ConfirmUntrusted(new[] { a })) return;
            try { Process.Start(LaunchInfo(a)); }
            catch (Win32Exception ex)
            {
                if (ex.NativeErrorCode != 1223) throw;
                SetStatus(a.Name + ": запуск отменён (права администратора не выданы).");
            }
            catch (Exception ex) { MessageBox.Show(this, a.Name + ": " + ex.Message, "WinUp"); }
        }

        // Как запускать: папка — Проводник, .ps1 — PowerShell (окно не закрывается), .cmd/.bat — cmd /k, иначе сам файл.
        internal static ProcessStartInfo LaunchInfo(AppItem a)
        {
            var path = Paths.Full(a.File);
            var args = (a.Args ?? "").Replace("{root}", Paths.Root);
            ProcessStartInfo psi;
            if (Directory.Exists(path))
                psi = new ProcessStartInfo(path);
            else if (path.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                psi = new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -NoExit -File \"" + path + "\" " + args);
            else if (path.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".bat", StringComparison.OrdinalIgnoreCase))
                psi = new ProcessStartInfo("cmd.exe", "/k \"\"" + path + "\" " + args + "\"");
            else
                psi = new ProcessStartInfo(path, args);
            psi.UseShellExecute = true;
            psi.WorkingDirectory = Directory.Exists(path) ? path : (Path.GetDirectoryName(path) ?? Paths.Root);
            if (a.Admin) psi.Verb = "runas";
            return psi;
        }

        // Список изменён вне WinUp и не принят: перед запуском показать, что именно запустится.
        bool ConfirmUntrusted(IEnumerable<AppItem> items)
        {
            if (!appsUntrusted) return true;
            var lines = string.Join("\n", items.Select(a => "• " + a.Name + ":  " + Paths.Full(a.File) +
                (string.IsNullOrEmpty(a.Args) ? "" : "  " + a.Args) + (a.Admin ? "  [от администратора]" : "")));
            return MessageBox.Show(this, "Список программ был изменён вне WinUp, и вы его не приняли.\nБудет запущено:\n\n" + lines +
                "\n\nЗапустить? Если не узнаёте путь или параметры — нажмите «Нет».",
                "WinUp — проверьте перед запуском", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes;
        }

        void InstallChecked()
        {
            var sel = instList.CheckedItems.Cast<ListViewItem>().Select(i => (AppItem)i.Tag).ToList();
            if (sel.Count == 0) { MessageBox.Show(this, "Отметьте галочками, что установить.", "WinUp"); return; }
            if (!ConfirmUntrusted(sel)) return;
            if (Win.IsAdmin()) { using (var f = new InstallForm(sel, silentBox.Checked)) f.ShowDialog(this); return; }
            // Один запрос UAC на всю пачку: перезапуск себя с правами администратора. Процесс с правами
            // администратора получает отпечаток списка, который видит это окно, и сверяет его с файлом:
            // подмена apps.json между нажатием кнопки и UAC не пройдёт.
            var hash = Integrity.AppsHash();
            var expected = appsUntrusted ? appsTamperHash : Integrity.GetApps();
            if (hash != null && !string.IsNullOrEmpty(expected) && hash != expected)
            {
                MessageBox.Show(this, "Файл списка программ (apps.json) изменился, пока WinUp открыт, — не через WinUp.\n" +
                    "Установка отменена. Перезапустите WinUp: он покажет, что изменилось.", "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            var args = "--install " + string.Join(",", sel.Select(a => a.Id)) + (silentBox.Checked ? "" : " --manual") +
                       (hash != null ? " --apps-sha256 " + hash : "");
            try { Process.Start(new ProcessStartInfo(Application.ExecutablePath, args) { UseShellExecute = true, Verb = "runas" }); }
            catch (Win32Exception) { SetStatus("Установка отменена: права администратора не выданы."); }
        }

        // ---------------- Каталог (winget) ----------------

        readonly ListView wgList = NewList(true);
        readonly TextBox wgQuery = new TextBox { Width = 260, Margin = new Padding(3, 5, 3, 3) };
        readonly CheckBox wgSilent = new CheckBox { Text = "Тихо, без окон установщиков", Checked = true, AutoSize = true, Margin = new Padding(8, 8, 3, 3) };
        readonly Label wgInfo = new Label { Dock = DockStyle.Bottom, Height = 40, Padding = new Padding(6, 4, 6, 4), ForeColor = SystemColors.GrayText };
        readonly List<Button> wgButtons = new List<Button>();
        string wgView = "";      // что в списке: "search" | "upgrade" | "set"
        bool wgBusy;

        void BuildWingetTab()
        {
            var page = new TabPage("WinGet");
            wgList.Columns.Add("Программа", 250); wgList.Columns.Add("ID", 230); wgList.Columns.Add("Версия", 110);
            wgList.Columns.Add("Доступна", 110); wgList.Columns.Add("Примечание", 150);
            var top = Bar();
            top.Controls.Add(new Label { Text = "Найти:", AutoSize = true, Margin = new Padding(6, 8, 0, 3) });
            top.Controls.Add(wgQuery);
            wgButtons.Add(Btn(top, "Найти", async (s, e) => await WgSearch()));
            wgButtons.Add(Btn(top, "Проверить обновления", async (s, e) => await WgUpgrades()));
            wgButtons.Add(Btn(top, "Мой набор", async (s, e) => await WgShowSet()));
            wgQuery.KeyDown += async (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await WgSearch(); } };
            var bar = Bar();
            wgButtons.Add(Btn(bar, "Установить отмеченные", (s, e) => WgRun("install")));
            wgButtons.Add(Btn(bar, "Обновить отмеченные", (s, e) => WgRun("upgrade")));
            bar.Controls.Add(wgSilent);
            wgButtons.Add(Btn(bar, "Отметить все / снять", (s, e) =>
            {
                bool on = wgList.Items.Cast<ListViewItem>().Any(i => !i.Checked);
                foreach (ListViewItem i in wgList.Items) i.Checked = on;
            }));
            wgButtons.Add(Btn(bar, "Добавить в мой набор", (s, e) => WgAddToSet()));
            wgButtons.Add(Btn(bar, "Убрать из набора", (s, e) => WgRemoveFromSet()));
            wgInfo.Text = "Программы ставятся из официального каталога Windows (winget) с сайтов разработчиков — нужен интернет. " +
                          "«Мой набор» хранится в списке WinUp и переезжает вместе с ним. Установка и обновление означают согласие с лицензиями этих программ.";
            page.Controls.Add(wgList); page.Controls.Add(bar); page.Controls.Add(top); page.Controls.Add(wgInfo);
            ArrangeActions(page,new[]{top,bar},
                new ActionGroup("Поиск",new[]{(Control)wgQuery}.Concat(Actions(top,"Найти","Проверить обновления","Мой набор")).ToArray()),
                new ActionGroup("Установка",bar.Controls.Cast<Control>().Take(4).ToArray()),
                new ActionGroup("Набор",Actions(bar,"Добавить в мой набор","Убрать из набора")));
            tabs.TabPages.Add(page);
        }

        static WingetRow WgRowOf(ListViewItem i) { return (WingetRow)i.Tag; }

        void WgShow(string view, List<WingetRow> rows, Func<WingetRow, string> note)
        {
            wgView = view;
            wgList.BeginUpdate(); wgList.Items.Clear();
            foreach (var r in rows)
                wgList.Items.Add(new ListViewItem(new[] { r.Name, r.Id, r.Version ?? "", r.Available ?? "", note(r) }) { Tag = r });
            wgList.EndUpdate();
        }

        // winget ещё нет на ПК (чистая Windows 10, LTSC) — предлагаем «Установщик приложений».
        bool WgAvailable()
        {
            if (Winget.Version() != null) return true;
            if (MessageBox.Show(this, "Каталог winget недоступен: на этом ПК нет «Установщика приложений» (App Installer) или он устарел.\n\n" +
                    "Открыть официальную страницу загрузки?", "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                try { Process.Start(new ProcessStartInfo(Winget.GetUrl) { UseShellExecute = true }); } catch { }
            return false;
        }

        // Запрос к winget в фоне: окно не замирает, кнопки каталога на это время выключены.
        async Task<Winget.Result> WgQuery(string args, string what)
        {
            if (wgBusy) return null;
            wgBusy = true;
            foreach (var b in wgButtons) b.Enabled = false;
            UseWaitCursor = true;
            SetStatus(what + "...");
            try
            {
                if (!await Task.Run(() => Winget.Version() != null) && !WgAvailable()) return null;
                var r = await Task.Run(() => Winget.Run(args, CancellationToken.None));
                if (r.StartError != null) { SetStatus("winget не запустился: " + r.StartError); return null; }
                return r;
            }
            finally { wgBusy = false; foreach (var b in wgButtons) b.Enabled = true; UseWaitCursor = false; }
        }

        async Task WgSearch()
        {
            var q = wgQuery.Text.Trim();
            if (q.Length < 2) { SetStatus("Введите название программы (хотя бы 2 буквы)."); wgQuery.Focus(); return; }
            var r = await WgQuery(Winget.SearchArgs(q), "Ищу «" + q + "» в каталоге winget");
            if (r == null) return;
            var rows = Winget.ParseTables(r.Output);
            var mine = new HashSet<string>(store.Winget.Select(w => w.Id), StringComparer.OrdinalIgnoreCase);
            WgShow("search", rows, x => mine.Contains(x.Id) ? "в моём наборе" : (x.Match ?? ""));
            SetStatus(rows.Count == 0 ? "По запросу «" + q + "» ничего не найдено." : "Найдено: " + rows.Count + ". Отметьте нужные и нажмите «Установить отмеченные» или «Добавить в мой набор».");
        }

        async Task WgUpgrades()
        {
            var r = await WgQuery(Winget.UpgradesArgs(), "Проверяю обновления установленных программ");
            if (r == null) return;
            var rows = Winget.ParseTables(r.Output);
            Reminder.MarkChecked();
            RefreshUpdateBanner();
            WgShow("upgrade", rows, x => "есть обновление");
            foreach (ListViewItem i in wgList.Items) i.Checked = true;
            SetStatus(rows.Count == 0 ? "Обновлений нет — всё, что знает winget, свежее." : "Доступно обновлений: " + rows.Count + ". Снимите лишние галочки и нажмите «Обновить отмеченные».");
        }

        async Task WgShowSet()
        {
            if (store.Winget.Count == 0)
            {
                WgShow("set", new List<WingetRow>(), x => "");
                SetStatus("Мой набор пуст: найдите программы и нажмите «Добавить в мой набор».");
                return;
            }
            var r = await WgQuery(Winget.ListArgs(), "Проверяю, что из набора уже установлено");
            var installed = r == null ? new List<WingetRow>() : Winget.ParseTables(r.Output);
            var rows = store.Winget.Select(w =>
            {
                var have = installed.FirstOrDefault(x => string.Equals(x.Id, w.Id, StringComparison.OrdinalIgnoreCase));
                return new WingetRow { Name = w.Name, Id = w.Id, Version = have == null ? "" : have.Version, Available = have == null ? "" : have.Available };
            }).ToList();
            WgShow("set", rows, x => string.IsNullOrEmpty(x.Version) ? "не установлена" : !string.IsNullOrEmpty(x.Available) ? "есть обновление" : "установлена");
            foreach (ListViewItem i in wgList.Items) i.Checked = string.IsNullOrEmpty(WgRowOf(i).Version);
            int missing = rows.Count(x => string.IsNullOrEmpty(x.Version));
            SetStatus("Мой набор: " + rows.Count + ", не установлено: " + missing + "." +
                      (missing > 0 ? " Отмечены неустановленные — нажмите «Установить отмеченные»." : " Всё из набора уже установлено."));
        }

        void WgAddToSet()
        {
            var sel = wgList.CheckedItems.Cast<ListViewItem>().Select(WgRowOf).ToList();
            if (sel.Count == 0) { SetStatus("Отметьте галочками программы, которые добавить в набор."); return; }
            int added = 0;
            foreach (var r in sel)
                if (!store.Winget.Any(w => string.Equals(w.Id, r.Id, StringComparison.OrdinalIgnoreCase)))
                { store.Winget.Add(new WingetPackage { Id = r.Id, Name = r.Name }); added++; }
            if (!SaveApps()) return;
            foreach (ListViewItem i in wgList.Items) if (i.Checked && wgView == "search") i.SubItems[4].Text = "в моём наборе";
            SetStatus("Добавлено в мой набор: " + added + (sel.Count > added ? ", уже были: " + (sel.Count - added) : "") + ". Всего в наборе: " + store.Winget.Count + ".");
        }

        void WgRemoveFromSet()
        {
            var sel = wgList.CheckedItems.Cast<ListViewItem>().Select(WgRowOf).ToList();
            if (sel.Count == 0) { SetStatus("Отметьте галочками программы, которые убрать из набора."); return; }
            int removed = store.Winget.RemoveAll(w => sel.Any(r => string.Equals(r.Id, w.Id, StringComparison.OrdinalIgnoreCase)));
            if (!SaveApps()) return;
            if (wgView == "set") foreach (var i in wgList.CheckedItems.Cast<ListViewItem>().ToList()) wgList.Items.Remove(i);
            SetStatus("Убрано из набора: " + removed + ". Сами программы не удаляются. Осталось в наборе: " + store.Winget.Count + ".");
        }

        // Установка/обновление отмеченных: один UAC на всю пачку, как у установщиков из apps\.
        void WgRun(string action)
        {
            var ids = wgList.CheckedItems.Cast<ListViewItem>().Select(i => WgRowOf(i).Id).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (ids.Count == 0) { MessageBox.Show(this, "Отметьте галочками, что " + (action == "upgrade" ? "обновить." : "установить."), "WinUp"); return; }
            if (Win.IsAdmin()) { using (var f = new WingetForm(ids, action, wgSilent.Checked)) f.ShowDialog(this); return; }
            var args = "--winget " + action + " " + string.Join(",", ids) + (wgSilent.Checked ? "" : " --manual");
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath, args) { UseShellExecute = true, Verb = "runas" });
                SetStatus((action == "upgrade" ? "Обновление" : "Установка") + " запущена в отдельном окне (" + ids.Count + " шт.). После неё нажмите «" +
                          (wgView == "set" ? "Мой набор" : "Проверить обновления") + "», чтобы увидеть результат.");
            }
            catch (Win32Exception) { SetStatus("Отменено: права администратора не выданы."); }
        }

        // ---------------- Коды 2FA (как приложение-аутентификатор) ----------------

        readonly ListView otpList = NewList(false);
        readonly Panel otpLocked = new Panel { Dock = DockStyle.Fill }, otpOpen = new Panel { Dock = DockStyle.Fill };
        readonly System.Windows.Forms.Timer otpTimer = new System.Windows.Forms.Timer { Interval = 1000 };

        void BuildCodesTab()
        {
            var page = new TabPage("2FA");
            var lbl = new Label { AutoSize = true, MaximumSize = new Size(640, 0), Location = new Point(20, 20),
                Text = "Коды 2FA хранятся в той же зашифрованной базе, что и пароли, и открываются тем же паролем базы.\n" +
                       "Открыли «Пароли» — открыта и эта вкладка." };
            var btn = new Button { Text = "Открыть...", AutoSize = true, Location = new Point(20, 80) };
            btn.Click += (s, e) => Unlock();
            otpLocked.Controls.Add(lbl); otpLocked.Controls.Add(btn);

            otpList.MultiSelect = false;
            otpList.Font = new Font("Segoe UI", 10f);
            otpList.Columns.Add("Сервис", 210); otpList.Columns.Add("Аккаунт", 250); otpList.Columns.Add("Код", 130); otpList.Columns.Add("Осталось", 90);
            var bar = Bar();
            Btn(bar, "Копировать код", (s, e) => CopyOtp());
            Btn(bar, "Добавить...", (s, e) => AddOtp());
            Btn(bar, "Импорт из другого приложения...", (s, e) => ImportOtp());
            Btn(bar, "История / корзина…", (s, e) => ShowRecordArchive(SelectedOtp()==null?null:SelectedOtp().Id,true));
            Btn(bar, "Изменить...", (s, e) => EditOtp());
            Btn(bar, "Удалить", (s, e) => DeleteOtp());
            otpList.DoubleClick += (s, e) => CopyOtp();
            var hint = new Label { Dock = DockStyle.Bottom, Height = 36, Padding = new Padding(6), ForeColor = SystemColors.GrayText,
                Text = "Двойной щелчок — скопировать код. Коды те же, что в приложении на телефоне, если там добавлен тот же аккаунт." };
            otpOpen.Controls.Add(otpList); otpOpen.Controls.Add(bar); otpOpen.Controls.Add(hint);
            ArrangeActions(otpOpen,new[]{bar},new ActionGroup("Код",Actions(bar,"Копировать код")),new ActionGroup("Аккаунты",Actions(bar,"Добавить...","Изменить...","Импорт из другого приложения...","Удалить","История / корзина…")));
            page.Controls.Add(otpOpen); page.Controls.Add(otpLocked);
            tabs.TabPages.Add(page);
            otpTimer.Tick += (s, e) => TickCodes();
            otpTimer.Start();
        }

        OtpEntry SelectedOtp() { return otpList.SelectedItems.Count > 0 ? (OtpEntry)otpList.SelectedItems[0].Tag : null; }

        static readonly Font CodeFont = new Font("Consolas", 13f, FontStyle.Bold); // один на все строки — не течёт

        void RefreshOtp()
        {
            if (vault == null) return;
            var sel = SelectedOtp() == null ? null : SelectedOtp().Id;
            otpList.BeginUpdate(); otpList.Items.Clear();
            foreach (var o in vault.Otp.OrderBy(x => x.Issuer, StringComparer.CurrentCultureIgnoreCase).ThenBy(x => x.Account))
            {
                var it = new ListViewItem(new[] { o.Issuer, o.Account ?? "", "", "" }) { Tag = o, UseItemStyleForSubItems = false };
                it.SubItems[2].Font = CodeFont;
                otpList.Items.Add(it);
                if (o.Id == sel) it.Selected = true;
            }
            otpList.EndUpdate();
            TickCodes();
        }

        static string Pretty(string code) { return code.Length == 6 ? code.Substring(0, 3) + " " + code.Substring(3) : code.Length == 8 ? code.Substring(0, 4) + " " + code.Substring(4) : code; }

        void TickCodes()
        {
            if (vault == null || !otpOpen.Visible || otpList.Items.Count == 0) return;
            foreach (ListViewItem it in otpList.Items)
            {
                var o = (OtpEntry)it.Tag;
                string code, left;
                try { code = Pretty(Totp.Code(o)); left = Totp.SecondsLeftFor(o.Period) + " с"; }
                catch (FormatException) { code = "ошибка"; left = ""; }
                if (it.SubItems[2].Text != code) it.SubItems[2].Text = code;
                if (it.SubItems[3].Text != left) it.SubItems[3].Text = left;
                it.SubItems[3].ForeColor = Totp.SecondsLeftFor(o.Period) <= 5 ? Color.Firebrick : SystemColors.GrayText;
            }
        }

        void CopyOtp()
        {
            var o = SelectedOtp();
            if (o == null) return;
            SecureClip.Copy(Totp.Code(o));
            SetStatus(o.Title + ": код скопирован, действует ещё " + Totp.SecondsLeftFor(o.Period) + " с. Буфер очистится через 30 с.");
        }

        void AddOtp()
        {
            if (vault == null) return;
            var o = new OtpEntry { Id = AppStore.NewId() };
            using (var d = new OtpDialog(o, true))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (vault == null) { PwLog("База заблокирована — аккаунт 2FA не сохранён."); return; }
                vault.Otp.Add(o);
                if (SaveVault()) { RefreshOtp(); SetStatus("Добавлен аккаунт 2FA: " + o.Title + "."); }
            }
        }

        void ImportOtp()
        {
            if (vault == null) return;
            using (var d = new OtpImportDialog(vault.Otp))
            {
                if (d.ShowDialog(this) != DialogResult.OK || d.Selected.Count == 0) return;
                if (vault == null) { PwLog("База заблокирована — импорт 2FA отменён."); return; }
                vault.Otp.AddRange(d.Selected);
                if (SaveVault()) { RefreshOtp(); PwLog("Импортировано аккаунтов 2FA: " + d.Selected.Count + "." + BackupNote()); SetStatus("Импортировано аккаунтов 2FA: " + d.Selected.Count + "."); }
            }
        }

        void EditOtp()
        {
            if (vault == null) return;
            var o = SelectedOtp();
            if (o == null) return;
            var copy = Json.Read<OtpEntry>(Json.Write(o, false));
            using (var d = new OtpDialog(copy, false))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (vault == null) { PwLog("База заблокирована — изменения не сохранены."); return; }
                vault.Otp[vault.Otp.IndexOf(o)] = copy;
                if (SaveVault()) RefreshOtp();
            }
        }

        void DeleteOtp()
        {
            if (vault == null) return;
            var o = SelectedOtp();
            if (o == null) return;
            var used = vault.Entries.Where(x => x.TwoFa == "link" && x.OtpId == o.Id).ToList();
            var current=vault;
            var msg = "Переместить аккаунт 2FA «" + o.Title + "» в корзину?\n\nЕго можно вернуть через «История / корзина…».";
            if (used.Count > 0) msg += "\n\nОн используется в записях: " + string.Join(", ", used.Select(x => x.Name)) + " — у них 2FA станет «Спросить код».";
            if (MessageBox.Show(this, msg, "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            if (vault != current) { PwLog("База изменилась во время подтверждения — удаление отменено."); return; }
            foreach (var x in used) { x.TwoFa = "ask"; x.OtpId = null; }
            vault.Otp.Remove(o);
            if (SaveVault()) {o.ClearSecret();RefreshOtp();}
        }

        // ---------------- Меню: мастер, поиск установщиков, передача, экспорт, справка ----------------

        void BuildMenu()
        {
            var menu = new MenuStrip();
            var m = new ToolStripMenuItem("Меню");
            m.DropDownItems.Add("Мастер первого запуска...", null, async (s, e) => await RunWizard());
            m.DropDownItems.Add("Найти установщики на ПК...", null, async (s, e) => await FindInstallers());
            m.DropDownItems.Add("Подготовить копию для передачи...", null, (s, e) => PrepareShare());
            m.DropDownItems.Add("Архив для переноса на другой ПК...", null, (s, e) => MakeTransferArchive());
            m.DropDownItems.Add("Экспорт паролей...", null, (s, e) => ExportPasswords());
            m.DropDownItems.Add("Защита от подбора пароля...", null, (s, e) => TuneKdf());
            m.DropDownItems.Add("PIN-код быстрой разблокировки...", null, (s, e) => SetupPin());
            m.DropDownItems.Add("Вход по Windows Hello...", null, (s, e) => SetupHello());
            m.DropDownItems.Add("Расширение для браузера...", null, (s, e) => ShowBrowserDialog());
            var remind = new ToolStripMenuItem("Напоминать о проверке обновлений") { CheckOnClick = true, Checked = Reminder.Enabled };
            remind.Click += (s, e) => { Reminder.Enabled = remind.Checked; RefreshUpdateBanner(); };
            m.DropDownItems.Add(remind);
            var capture = new ToolStripMenuItem("Скрывать окна WinUp от записи экрана") { CheckOnClick = true, Checked = store.Settings.HideFromCapture };
            capture.Click += (s, e) =>
            {
                store.Settings.HideFromCapture = capture.Checked;
                SaveApps();
                Win.SetCaptureProtection(capture.Checked);
                PwLog(capture.Checked
                    ? "Защита от записи экрана включена: скриншоты, запись и удалённый доступ не видят окна WinUp."
                    : "Защита от записи экрана выключена: окна WinUp видны на скриншотах и при удалённом доступе.");
            };
            m.DropDownItems.Add(capture);
            var minimizeToTray = new ToolStripMenuItem("Сворачивать в трей")
                { CheckOnClick = true, Checked = store.Settings.MinimizeToTray };
            minimizeToTray.Click += (s, e) =>
            {
                store.Settings.MinimizeToTray = minimizeToTray.Checked;
                SaveApps();
            };
            m.DropDownItems.Add(minimizeToTray);
            m.DropDownItems.Add(new ToolStripSeparator());
            m.DropDownItems.Add("Справка (инструкция)", null, (s, e) => OpenHelp());
            m.DropDownItems.Add("О программе", null, (s, e) => ShowAbout());
            m.DropDownItems.Add("Обновления компонентов...", null, (s, e) => ShowComponentUpdates());
            m.DropDownItems.Add("Выход", null, (s, e) => Close());
            menu.Items.Add(m);
            var help = new ToolStripMenuItem("Справка", null, (s, e) => OpenHelp());
            menu.Items.Add(help);
            lockMenu = new ToolStripMenuItem("🔒 База закрыта") { Alignment = ToolStripItemAlignment.Right, Enabled = false, ToolTipText = "Заблокировать базу паролей (Ctrl+L)" };
            lockMenu.Click += (s, e) => { LockVault(); PwLog("Выполнена общая блокировка."); };
            menu.Items.Add(lockMenu);
            Controls.Add(menu);
            MainMenuStrip = menu;
        }

        void BuildUpdateBanner()
        {
            // Кнопки прижаты вправо и видны при любой ширине окна; текст слева сокращается многоточием.
            var flow = new FlowLayoutPanel { Dock = DockStyle.Right, AutoSize = true, WrapContents = false, Padding = new Padding(0, 0, 4, 0) };
            var tips = new ToolTip();
            Action<string, string, EventHandler> add = (text, tip, click) =>
            {
                var b = new Button { Text = text, AutoSize = true, Margin = new Padding(3, 5, 3, 3) };
                b.Click += click;
                if (tip != null) tips.SetToolTip(b, tip);
                if (text.Length == 1) { b.AutoSize = false; b.Size = new Size(30, 25); } // ✕ — без стандартной ширины кнопки
                flow.Controls.Add(b);
            };
            add("Проверить крипто-ядро", "Сверить версию шифрования с keepass.info и при необходимости обновить", (s, e) => ShowAbout(true));
            add("Обновления программ", "Вкладка «WinGet» → список программ, для которых есть новые версии", async (s, e) =>
            {
                SelectTab("WinGet");
                await WgUpgrades();
            });
            add("Через месяц", "Напомнить через 30 дней", (s, e) => { Reminder.Snooze(30); RefreshUpdateBanner(); });
            add("✕", "Скрыть до завтра. Отключить совсем: Меню → «Напоминать о проверке обновлений»", (s, e) => { Reminder.Snooze(1); RefreshUpdateBanner(); });
            updText.AutoSize = false;
            updText.Dock = DockStyle.Fill;
            updText.AutoEllipsis = true;
            updText.TextAlign = ContentAlignment.MiddleLeft;
            updText.Padding = new Padding(8, 0, 0, 0);
            updBanner.Controls.Add(updText);
            updBanner.Controls.Add(flow);
            Controls.Add(updBanner);
        }

        void RefreshUpdateBanner()
        {
            updShownDay = DateTime.Today;
            var text = Reminder.Due(DateTime.Today);
            if (text != null) updText.Text = text;
            updBanner.Visible = text != null;
        }

        // Контрольная сумма своего exe: пользователь сверяет её со значением, сохранённым вне этого ПК.
        // autoCheck — открыто с плашки напоминания: проверка обновления ядра запускается сразу.
        void ShowAbout(bool autoCheck = false)
        {
            string hash;
            try
            {
                using (var sha = System.Security.Cryptography.SHA256.Create())
                using (var f = File.OpenRead(Application.ExecutablePath))
                    hash = BitConverter.ToString(sha.ComputeHash(f)).Replace("-", "");
            }
            catch (Exception ex) { hash = "не удалось вычислить: " + ex.Message; }
            using (var d = new AboutDialog(hash, PwLog, autoCheck)) d.ShowDialog(this);
            RefreshUpdateBanner();

            RestartAfterComponentUpdate();
        }

        void ShowComponentUpdates()
        {
            using(var dialog=new ComponentUpdatesDialog(PwLog,delegate { ShowAbout(true); },delegate { LockVault(); })) dialog.ShowDialog(this);
            RestartAfterComponentUpdate();
        }

        void RestartAfterComponentUpdate()
        {

            // Пользователь подтвердил перезапуск для применения обновления крипто-ядра.
            if (CoreUpdate.RestartPendingFlag)
            {
                CoreUpdate.RestartPendingFlag = false;
                try
                {
                    var me = System.Diagnostics.Process.GetCurrentProcess().Id;
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                        Application.ExecutablePath, "--wait " + me));
                }
                catch { return; }
                Close(); // FormClosed заблокирует базу и очистит буфер; мьютекс освободится при выходе
            }
        }

        // Уведомления сеанса Windows: блокировка экрана (Win+L) блокирует и базу паролей.
        // Главное окно (список записей, коды 2FA) — вне записи экрана, если защита включена.
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Win.SessionNotifyRegister(Handle);
            Win.ApplyCaptureProtection(this);
            RegisterAutoTypeHotkey();
        }

        protected override void OnHandleDestroyed(EventArgs e)
        {
            if(autoTypeRegistered){UnregisterHotKey(Handle,AutoTypeHotkeyId);autoTypeRegistered=false;}
            Win.SessionNotifyUnregister(Handle);
            base.OnHandleDestroyed(e);
        }

        protected override void WndProc(ref Message m)
        {
            if(m.Msg==0x0312&&m.WParam.ToInt32()==AutoTypeHotkeyId){BeginAutoTypeForeground();return;}
            if (m.Msg == Win.WmShowWinUp)
            {
                ShowFromTray();
                return;
            }
            if (m.Msg == Win.WmWtsSessionChange && m.WParam.ToInt32() == Win.WtsSessionLock)
            {
                LockVault();
                PwLog("Заблокировано вместе с Windows (Win+L).");
            }
            base.WndProc(ref m);
        }

        void OpenHelp()
        {
            var p = Path.Combine(Paths.Root, "Инструкция.html");
            // Инструкция вложена в exe (ресурс help.html): если файла нет рядом
            // (WinUp передали одним файлом), извлекаем встроенную копию и открываем её.
            if (!File.Exists(p))
            {
                try { Paths.CopyBundled("Инструкция.html", p); }
                catch { }
            }
            if (!File.Exists(p)) { MessageBox.Show(this, "Файл инструкции не найден:\n" + p, "WinUp"); return; }
            try { Process.Start(new ProcessStartInfo(p) { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "WinUp"); }
        }

        async Task RunWizard()
        {
            using (var w = new WizardForm(FindInstallers, () => { if (vault == null && !BaseExists()) CreateVault(); return vault != null || BaseExists(); }, OpenHelp, BaseExists()))
                w.ShowDialog(this);
            store.Settings.WizardDone = true;
            SaveApps();
            await Task.FromResult(0);
        }

        static string Describe(string path)
        {
            try
            {
                var v = FileVersionInfo.GetVersionInfo(path);
                var desc = (v.FileDescription ?? "").Trim();
                var product = (v.ProductName ?? "").Trim();
                var company = (v.CompanyName ?? "").Trim();
                var text = desc.Length > 1 && !string.Equals(desc, product, StringComparison.OrdinalIgnoreCase) ? desc : product;
                return (text + (company.Length > 1 ? " (" + company + ")" : "")).Trim();
            }
            catch { return ""; }
        }

        async Task<int> FindInstallers()
        {
            var known = new HashSet<string>();
            foreach (var a in store.Apps)
            {
                try { var p = Paths.Full(a.File); if (File.Exists(p)) known.Add(Path.GetFileName(p).ToLowerInvariant() + "|" + new FileInfo(p).Length); }
                catch { }
            }
            List<FoundFile> selected;
            using (var d = new InstallerSearchDialog(known))
            {
                if (d.ShowDialog(this) != DialogResult.OK || d.Selected.Count == 0) return 0;
                selected = d.Selected;
            }
            return await ImportFound(selected);
        }

        // Копирование найденных файлов в apps\ и добавление в список (оригиналы не трогаются).
        async Task<int> ImportFound(List<FoundFile> list)
        {
            int added = 0, i = 0;
            UseWaitCursor = true;
            try
            {
                Directory.CreateDirectory(Paths.Apps);
                foreach (var f in list)
                {
                    i++;
                    var dst = Path.Combine(Paths.Apps, Path.GetFileName(f.Path));
                    // Сверяем и время изменения: обновление того же размера раньше не копировалось молча.
                    if (File.Exists(dst))
                    {
                        var old = new FileInfo(dst);
                        if (old.Length != f.Size || old.LastWriteTimeUtc != File.GetLastWriteTimeUtc(f.Path))
                        {
                            var stem = Path.GetFileNameWithoutExtension(f.Path); var ext = Path.GetExtension(f.Path);
                            for (int n = 2; File.Exists(dst); n++) dst = Path.Combine(Paths.Apps, stem + " (" + n + ")" + ext);
                        }
                    }
                    if (!File.Exists(dst))
                    {
                        SetStatus("Копирую " + i + " из " + list.Count + ": " + Path.GetFileName(f.Path) + " ...");
                        var from = f.Path; var to = dst;
                        try { await Task.Run(() => File.Copy(from, to)); }
                        catch (Exception ex) { MessageBox.Show(this, "Не удалось скопировать " + from + ":\n" + ex.Message, "WinUp"); continue; }
                    }
                    var rel = Paths.Rel(dst);
                    if (store.Apps.Any(a => string.Equals(a.File, rel, StringComparison.OrdinalIgnoreCase))) continue;
                    store.Apps.Add(new AppItem { Id = AppStore.NewId(), Name = f.Name, File = rel, Kind = f.Kind, Args = f.Args, Note = f.Note, Description = f.Description });
                    added++;
                }
            }
            finally { UseWaitCursor = false; }
            SaveApps();
            SetStatus("Добавлено программ: " + added + ".");
            return added;
        }

        // Копия WinUp для другого человека: exe, пустая apps, шаблоны и ссылки — без программ, паролей и личных настроек.
        void PrepareShare()
        {
            string parent;
            using (var d = new FolderBrowserDialog { Description = "Куда положить копию WinUp для передачи (будет создана папка WinUp)", ShowNewFolderButton = true })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                parent = d.SelectedPath;
            }
            string target;
            try { target = Share.Make(store, parent, Application.ExecutablePath); }
            catch (Exception ex) { MessageBox.Show(this, "Не удалось подготовить копию:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
            if (MessageBox.Show(this, "Готово: " + target + "\n\nВнутри: WinUp.exe (шифрование встроено), пустая папка apps, шаблоны входа (" +
                    store.Templates.Count(t => t.Group != "Мои") + ") и ссылки (" + store.Links.Count + ").\n" +
                    "Нет: ваших программ, паролей, личных шаблонов «Мои» и настроек.\n\nПапку можно упаковать в архив и отправить. Открыть её?",
                    "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                Process.Start("explorer.exe", "\"" + target + "\"");
        }

        // Архив для переноса на другой ПК: программа, база, счётчики попыток, код восстановления,
        // папка apps с программами и настройки — одним zip-файлом. На новом ПК: распаковать и запустить.
        void MakeTransferArchive()
        {
            using (var d = new SaveFileDialog { Title = "Куда сохранить архив для переноса", FileName = "WinUp — перенос " + DateTime.Now.ToString("yyyy-MM-dd") + ".zip", Filter = "Архив (*.zip)|*.zip" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                long size = 0;
                try { Busy(() => { size = MakeTransferZip(d.FileName); return 0; }); }
                catch (Exception ex) { MessageBox.Show(this, "Не удалось создать архив:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
                MessageBox.Show(this, "Архив создан: " + d.FileName + " (" + Mb(size) + ").\n\n" +
                    "На новом ПК: распакуйте архив в любую папку и запустите WinUp.exe — база, программы и настройки уже внутри.\n" +
                    "Папка резерва (" + store.Settings.BackupDir + ") в архив не входит: если нужна — перенесите отдельно.",
                    "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Information);
                Process.Start("explorer.exe", "/select,\"" + d.FileName + "\"");
            }
        }

        // Остатки атомарной записи (.tmp/.bak) и аварийные выгрузки экспорта (export-*.xml с паролями открытым
        // текстом) в архив не берём. Ядро шифрования вшито в exe. Обновлённое ядро из data\core тоже не берём:
        // копия использует встроенный проверенный минимум; при необходимости ядро обновляют через меню.
        long MakeTransferZip(string path)
        {
            if (File.Exists(path)) File.Delete(path);
            long total = 0;
            using (var zip = System.IO.Compression.ZipFile.Open(path, System.IO.Compression.ZipArchiveMode.Create))
            {
                zip.CreateEntryFromFile(Application.ExecutablePath, "WinUp.exe", System.IO.Compression.CompressionLevel.Fastest);
                total += new FileInfo(Application.ExecutablePath).Length;
                // Лицензия ядра и инструкция — из папки или из exe (если WinUp пришёл одним файлом).
                foreach (var name in Paths.Bundled)
                    using (var s = Paths.OpenBundled(name))
                    {
                        if (s == null) continue;
                        using (var e = zip.CreateEntry(name, System.IO.Compression.CompressionLevel.Fastest).Open()) s.CopyTo(e);
                        total += s.Length;
                    }
                var coreDir = CoreLoader.CoreDir + "\\";
                Action<string, string> addDir = (dir, prefix) =>
                {
                    if (!Directory.Exists(dir)) return;
                    foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        var name = Path.GetFileName(f);
                        var ext = Path.GetExtension(f).ToLowerInvariant();
                        if (ext == ".tmp" || ext == ".bak" || name.StartsWith("export-", StringComparison.OrdinalIgnoreCase)) continue;
                        if (f.StartsWith(coreDir, StringComparison.OrdinalIgnoreCase) && name.StartsWith(CoreLoader.FileName, StringComparison.OrdinalIgnoreCase)) continue;
                        var rel = prefix + f.Substring(dir.Length).TrimStart('\\').Replace('\\', '/');
                        zip.CreateEntryFromFile(f, rel, System.IO.Compression.CompressionLevel.Fastest);
                        total += new FileInfo(f).Length;
                    }
                };
                addDir(Paths.Data, "data/");
                addDir(Paths.Apps, "apps/");
                var readme = "WinUp — перенос на другой ПК\r\n\r\n" +
                    "1. Распакуйте архив в любую папку (например, C:\\WinUp).\r\n" +
                    "2. Запустите WinUp.exe.\r\n" +
                    "3. Вкладка «Пароли» → «Открыть...» → введите пароль базы — записи, коды 2FA, программы и настройки уже на месте.\r\n\r\n" +
                    "Папка резерва (" + store.Settings.BackupDir + ") в архив не входит: если нужна, скопируйте её отдельно.\r\n" +
                    "WinUp.exe в архиве тот же, что был у вас, — контрольная сумма для проверки (меню «О программе») не меняется.";
                var entry = zip.CreateEntry("README — перенос.txt");
                using (var w = new StreamWriter(entry.Open(), new System.Text.UTF8Encoding(true))) w.Write(readme);
            }
            return total;
        }

        void TuneKdf()
        {
            if (vault == null) { MessageBox.Show(this, "Сначала откройте базу паролей.", "WinUp"); return; }
            var current = vault;
            using (var d = new KdfDialog(current.KdfMemoryMiB, current.KdfIterations))
            {
                if (d.ShowDialog(this) != DialogResult.OK || vault != current) return;
                try
                {
                    var result = Busy(() => current.CalibrateKdf(d.MemoryMiB, d.TargetMilliseconds));
                    if (vault != current) return;
                    if (MessageBox.Show(this, "Измерено: " + result.MemoryMiB + " МБ, итераций: " + result.Iterations +
                        ", время: " + result.Milliseconds + " мс.\n\nСохранить эту защиту базы?", "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes || vault != current) return;
                    current.ApplyKdf(result);
                    if (SaveVault()) PwLog("Защита от подбора: Argon2, " + result.MemoryMiB + " МБ, итераций: " + result.Iterations + ".");
                }
                catch (Exception ex) { MessageBox.Show(this, "Не удалось настроить защиту:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }

        void ExportPasswords()
        {
            if (vault == null)
            {
                MessageBox.Show(this, "Сначала откройте вкладку «Пароли» (нужен пароль базы).", "WinUp");
                SelectTab("Пароли");
                return;
            }
            if (!ConfirmDbPassword("Экспорт паролей")) return;
            using (var d = new ExportDialog())
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (vault == null) { PwLog("База заблокирована — экспорт отменён."); return; }
                var key = d.OwnKey ?? Export.NewKey();
                try
                {
                var entries = vault.Entries.OrderBy(x => x.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
                var stem = "WinUp-пароли-" + DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                var made = new List<string>();
                try
                {
                    Directory.CreateDirectory(d.Folder);
                    if (d.Kdbx)
                    {
                        // База WinUp — уже стандартный .kdbx: копия открывается в KeePassXC и на телефоне
                        // вашим паролем базы (+ ключ-файлом, если он есть).
                        var p = Path.Combine(d.Folder, stem + ".kdbx");
                        Busy(() => { Export.CopyEncryptedDatabase(KdbxStore.KdbxFile, p); return 0; });
                        if (vault == null) throw new InvalidOperationException("база заблокирована во время экспорта");
                        made.Add(p);
                    }
                    if (d.Zip)
                    {
                        var p = Path.Combine(d.Folder, stem + ".zip");
                        var files = new List<KeyValuePair<string, byte[]>>();
                        try
                        {
                        files.Add(new KeyValuePair<string, byte[]>("пароли.csv", Export.Csv(entries, vault.Otp)));
                        files.Add(new KeyValuePair<string, byte[]>("пароли.txt", Export.Text(entries, vault.Otp)));
                        if (vault.Otp.Count > 0) files.Add(new KeyValuePair<string, byte[]>("коды-2fa.txt", Export.OtpLinks(vault.Otp)));
                        Busy(() => { Export.ZipAes(p, files, key); return 0; });
                        }
                        finally { foreach (var file in files) Array.Clear(file.Value, 0, file.Value.Length); }
                        made.Add(p);
                    }
                }
                catch (Exception ex) { MessageBox.Show(this, "Ошибка экспорта:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                if (made.Count == 0) return;
                PwLog("Экспорт (" + entries.Count + " записей): " + string.Join(", ", made));
                var where = string.Join("\n", made);
                if (d.Zip && d.OwnKey == null)
                    using (var k = new KeyDialog("Ключ к экспорту", "Созданы файлы:\n" + where + "\n\nАрхив .zip открывается только этим ключом. Запишите его и храните отдельно от файлов.",
                               key, stem + " — ключ.txt"))
                        k.ShowDialog(this);
                else MessageBox.Show(this, "Созданы файлы:\n" + where, "WinUp");
                Process.Start("explorer.exe", "/select,\"" + made[0] + "\"");
                }
                finally { Secure.Wipe(key); }
            }
        }

        // ---------------- Поиск новых файлов в apps\ ----------------

        static readonly string[] ScanExt = { ".exe", ".msi", ".ps1", ".cmd", ".bat" };

        async Task ScanNew(bool auto)
        {
            if (!Directory.Exists(Paths.Apps)) { if (!auto) MessageBox.Show(this, "Папки нет: " + Paths.Apps, "WinUp"); return; }
            List<AppItem> found;
            UseWaitCursor = true;
            try { found = await Task.Run(() => FindNew()); }
            finally { UseWaitCursor = false; }
            if (found.Count == 0) { if (!auto) MessageBox.Show(this, "Новых файлов в apps\\ нет.", "WinUp"); return; }
            using (var d = new ScanDialog(found))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                foreach (var a in d.ToAdd) { a.Id = AppStore.NewId(); store.Apps.Add(a); }
                // Дубликаты в «больше не предлагать» не копим: список в apps.json не должен пухнуть.
                var ignoredSet = new HashSet<string>(store.Settings.IgnoredFiles, StringComparer.OrdinalIgnoreCase);
                foreach (var x in d.ToIgnore) if (ignoredSet.Add(x)) store.Settings.IgnoredFiles.Add(x);
                SaveApps();
                SetStatus("Добавлено из apps: " + d.ToAdd.Count + (d.ToIgnore.Count > 0 ? ", больше не предлагать: " + d.ToIgnore.Count : "") +
                          ". Описание можно дописать в «Изменить...».");
            }
        }

        // Смотрим верхний уровень apps\ и подпапки, которые ещё не используются ни одной записью
        // (иначе, например, папка Sysinternals дала бы сотню «новых» exe).
        List<AppItem> FindNew()
        {
            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var usedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Action<string> use = full => { if (full.Length == 0) return; known.Add(full); var d = TopDir(full); if (d != null) usedDirs.Add(d); };
            foreach (var a in store.Apps)
            {
                use(SafeFull(a.File));
                // Файлы, на которые ссылаются параметры запуска: {root}\apps\...
                foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(a.Args ?? "", @"\{root\}\\(apps\\[^""']+)"))
                    use(SafeFull(m.Groups[1].Value.Trim()));
            }
            var ignored = new HashSet<string>(store.Settings.IgnoredFiles, StringComparer.OrdinalIgnoreCase);
            var files = new List<string>();
            string[] top = null, dirs = null;
            try { top = Directory.GetFiles(Paths.Apps); } catch { }
            if (top != null) files.AddRange(top);
            try { dirs = Directory.GetDirectories(Paths.Apps); } catch { }
            if (dirs != null)
                foreach (var dir in dirs)
                    if (!usedDirs.Contains(dir)) files.AddRange(SafeGetFiles(dir));

            var result = new List<AppItem>();
            foreach (var f in files)
            {
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (!ScanExt.Contains(ext)) continue;
                var rel = Paths.Rel(f);
                if (known.Contains(f) || ignored.Contains(rel)) continue;
                // Название — из свойств файла («Telegram Desktop», а не «tsetup-x64.5.8.3»), как при поиске установщиков на ПК.
                var a = new AppItem { Name = FriendlyName(f), File = rel, Args = "", Note = "", Description = Describe(f) };
                if (ext == ".exe" || ext == ".msi")
                {
                    string args, note;
                    bool installer = Detect.Guess(f, out args, out note);
                    a.Kind = installer ? "install" : "portable";
                    if (installer) { a.Args = args; a.Note = note; } else a.Note = "установщик не распознан — предлагаю как портативную";
                }
                else { a.Kind = "portable"; a.Note = "скрипт"; }
                result.Add(a);
                if (result.Count >= 300) break;
            }
            return result;
        }

        static string FriendlyName(string path)
        {
            var file = Path.GetFileNameWithoutExtension(path);
            try
            {
                var product = (FileVersionInfo.GetVersionInfo(path).ProductName ?? "").Trim();
                if (product.Length > 1 && !System.Text.RegularExpressions.Regex.IsMatch(product, @"^(setup|installer|google installer)$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    return product;
            }
            catch { }
            return file;
        }

        static string SafeFull(string p) { try { return Path.GetFullPath(Paths.Full(p)); } catch { return ""; } }

        // apps\X\... или сама папка apps\X → полный путь к apps\X; файл прямо в apps\ → null.
        static string TopDir(string full)
        {
            var apps = Paths.Apps + "\\";
            if (!full.StartsWith(apps, StringComparison.OrdinalIgnoreCase)) return null;
            var rest = full.Substring(apps.Length);
            int i = rest.IndexOf('\\');
            if (i < 0) return Directory.Exists(full) ? full : null;
            return Path.Combine(Paths.Apps, rest.Substring(0, i));
        }

        // ---------------- Пароли ----------------

        readonly ComboBox browserBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 240 };
        bool askedRecovery, fillingBrowsers;
        // Отмена автовхода при блокировке базы: пароли не печатаются в чужие окна после Win+L (ревью R-4).
        CancellationTokenSource loginCts;
        // Растёт при каждой блокировке: вход, начатый до блокировки, не применяет свой результат
        // (за время Busy-качания сообщений могла прийти блокировка Win+L и затереть объект).
        int lockGen;
        bool unlockBusy;

        void BuildPasswordTab()
        {
            var page = new TabPage("Пароли");
            lockedPanel.Controls.Add(lockedText); lockedPanel.Controls.Add(unlockBtn);
            unlockBtn.Click += (s, e) => Unlock();

            pwList.CheckBoxes = true; pwList.MultiSelect = false;
            pwList.Columns.Add("Название", 160); pwList.Columns.Add("Тип", 75); pwList.Columns.Add("Логин", 130);
            pwList.Columns.Add("Адрес / программа", 200); pwList.Columns.Add("Окно", 110); pwList.Columns.Add("Enter", 45);
            pwList.Columns.Add("2FA", 75); pwList.Columns.Add("Браузер", 90);
            pwList.Columns.Add("Категория",140).DisplayIndex=2;

            var bar = Bar();
            Btn(bar, "Войти", async (s, e) => await LoginSelected());
            Btn(bar, "Войти в отмеченные", async (s, e) => await LoginChecked());
            Btn(bar, "Копировать логин", (s, e) => CopyField(true));
            Btn(bar, "Копировать пароль", (s, e) => CopyField(false));
            Btn(bar, "Код 2FA", (s, e) => CopyTotp());
            Btn(bar, "Добавить...", (s, e) => AddEntry());
            Btn(bar, "Импорт паролей…", (s, e) => {try{ImportPasswords();}catch(Exception ex){MessageBox.Show(this,ex.Message,"WinUp — импорт паролей");}});
            Btn(bar, "Изменить...", (s, e) => EditEntry());
            Btn(bar, "Проверить адреса…", (s, e) => ReviewAccountAddresses());
            Btn(bar, "Дополнительные поля…", (s, e) => EditSelectedFields());
            Btn(bar,"Вложения…",(s,e)=>ManageAttachments());
            Btn(bar,"Ссылки между полями…",(s,e)=>ManageReferences());
            Btn(bar,"Автоввод в приложение…",(s,e)=>EditApplicationAutoType());
            Btn(bar, "Изменить отмеченные…", (s, e) => BulkEditPasswords());
            Btn(bar, "История / корзина…", (s, e) => ShowRecordArchive(SelectedEntry()==null?null:SelectedEntry().Id));
            Btn(bar, "Закрепить / открепить", (s, e) => TogglePinnedPassword());
            Btn(bar, "Удалить", (s, e) => DeleteEntry());
            Btn(bar, "Генератор...", (s, e) => { using (var d = new GenDialog(false)) d.ShowDialog(this); });

            var bar2 = Bar();
            Btn(bar2,"Группы…",(s,e)=>ManageAccountGroups());
            Btn(bar2,"Объединить копии базы…",(s,e)=>MergeDatabaseCopies());
            Btn(bar2,"Автоввод / горячая клавиша…",(s,e)=>ConfigureAutoTypeHotkey());
            bar2.Controls.Add(new Label { Text = "Сайты открывать в:", AutoSize = true, Margin = new Padding(6, 8, 3, 3) });
            bar2.Controls.Add(browserBox);
            Btn(bar2, "Код восстановления...", (s, e) => MakeRecoveryCode(true));
            Btn(bar2, "Сменить пароль базы...", (s, e) => ChangePasswords());
            Btn(bar2, "Папка резерва...", (s, e) => ChangeBackupDir());
            Btn(bar2, "Заблокировать базу", (s, e) => { LockVaultCore(true); PwLog("Пароли / 2FA / ключи доступа закрыты; файлы остаются в прежнем состоянии."); });
            FillBrowsers();
            browserBox.SelectedIndexChanged += (s, e) =>
            {
                if (fillingBrowsers) return;
                store.Settings.Browser = browserBox.SelectedIndex <= 0 ? "" : ((string)browserBox.SelectedItem).Replace(" (нет на этом ПК)", "");
                SaveApps();
            };

            pwList.DoubleClick += async (s, e) => await LoginSelected();
            openPanel.Controls.Add(pwList); openPanel.Controls.Add(BuildPasswordFilters());openPanel.Controls.Add(bar); openPanel.Controls.Add(bar2);
            ArrangeActions(openPanel,new[]{bar,bar2},
                new ActionGroup("Вход",Actions(bar,"Войти","Войти в отмеченные","Копировать логин","Копировать пароль","Код 2FA","Автоввод в приложение…")),
                new ActionGroup("Записи",Actions(bar,"Добавить...","Изменить...","Импорт паролей…","Проверить адреса…","Закрепить / открепить","Генератор...","Удалить","Дополнительные поля…","Вложения…","Ссылки между полями…","Изменить отмеченные…","История / корзина…")),
                new ActionGroup("База / браузер",new[]{(Control)browserBox}.Concat(Actions(bar2,"Группы…","Объединить копии базы…","Автоввод / горячая клавиша…","Заблокировать базу","Код восстановления...","Сменить пароль базы...","Папка резерва...")).ToArray()));

            page.Controls.Add(openPanel); page.Controls.Add(lockedPanel); page.Controls.Add(pwLog);
            tabs.TabPages.Add(page);
        }

        void FillBrowsers()
        {
            fillingBrowsers = true;
            browserBox.Items.Clear();
            browserBox.Items.Add("Браузер по умолчанию (системный)");
            foreach (var b in Browsers.Installed()) browserBox.Items.Add(b.Name);
            var cur = store.Settings.Browser ?? "";
            if (cur.Length == 0) browserBox.SelectedIndex = 0;
            else
            {
                int i = browserBox.Items.IndexOf(cur);
                if (i < 0) i = browserBox.Items.Add(cur + " (нет на этом ПК)");
                browserBox.SelectedIndex = i;
            }
            fillingBrowsers = false;
        }

        // До первого показа вкладки «Пароли» у журнала нет хэндла, и AppendText молча теряет текст —
        // тогда копим в свойство Text (кэш выталкивается при создании хэндла).
        // Журнал «Пароли» (вкладка). internal: пишет и сервер канала расширения — только в потоке интерфейса.
        internal void PwLog(string m)
        {
            var line = "[" + DateTime.Now.ToString("HH:mm:ss") + "] " + m + "\r\n";
            if (pwLog.IsHandleCreated) pwLog.AppendText(line);
            else pwLog.Text += line;
        }

        // Журнал из фоновых потоков (сервер канала расширения) — через очередь потока интерфейса.
        internal void PwLogAsync(string m)
        {
            try
            {
                if (!IsHandleCreated) return;
                if (InvokeRequired) BeginInvoke((MethodInvoker)delegate { PwLog(m); });
                else PwLog(m);
            }
            catch { }
        }

        void ShowLocked()
        {
            openPanel.Visible = false; lockedPanel.Visible = true;
            otpOpen.Visible = false; otpLocked.Visible = true; otpList.Items.Clear();
            if (!BaseExists())
            {
                lockedText.Text = "База паролей ещё не создана.\n\nФайл базы: " + KdbxStore.KdbxFile +
                                  "\nРезервные копии: " + store.Settings.BackupDir +
                                  "\n\nЕсли база была уничтожена или потеряна — скопируйте последний файл vault-*.kdbx из папки резерва в " +
                                  KdbxStore.KdbxFile + " (откроется вашим паролем или кодом восстановления).";
                unlockBtn.Text = "Создать базу...";
            }
            else
            {
                lockedText.Text = "Вкладка заблокирована.\n\nНужен пароль базы (" + KdbxStore.P2Max + " попыток). При исчерпании попыток база уничтожается.\n" +
                                  "Забыли пароль — откройте базу кодом восстановления.";
                unlockBtn.Text = "Открыть...";
            }
            unlockBtn.Top = lockedText.Bottom + 16;
            UpdateLockUi();
        }

        void ShowOpen()
        {
            lockedPanel.Visible = false; openPanel.Visible = true;
            otpLocked.Visible = false; otpOpen.Visible = true;
            RefreshEntries();
            RefreshOtp();
            UpdateLockUi();
        }

        // Состояние базы — в значке окна и трея, кнопка «Заблокировать» в строке меню доступна с любой вкладки.
        void UpdateLockUi()
        {
            bool open = vault != null;
            if (tray != null) tray.SetLocked(!open);
            if (tray != null) tray.SetFilesOpen(fileVault!=null&&fileVault.Open);
            if (lockMenu != null) { lockMenu.Enabled = open || fileVault!=null; lockMenu.Text = "🔒 Заблокировать всё"; }
            Icon = open ? AppIcons.Open : AppIcons.Locked;
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            if (WindowState == FormWindowState.Minimized)
            {
                if (tray != null && store.Settings.MinimizeToTray) Hide();
            }
            else trayRestoreState = WindowState;
        }

        // Скрытое окно сохраняет хэндл: второй запуск и расширение тоже могут его восстановить.
        internal void ShowFromTray()
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = trayRestoreState;
            Activate(); // щелчок по значку трея даёт WinUp право вывести окно вперёд
        }

        // Ctrl+L — заблокировать базу с любой вкладки.
        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == (Keys.Control | Keys.L) && (vault != null || fileVault!=null || unlockBusy))
            {
                LockVault();
                PwLog("Заблокировано (Ctrl+L).");
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        void LockVault()
        {LockVaultCore(false);}
        void LockVaultCore(bool keepProject)
        {
            lockGen++;
            browserLogins.Clear();
            if(!keepProject) {
                CloseFileSecretDialogs();
                if(fileBusy) {fileLockRequested=true;if(fileCancellation!=null)fileCancellation.Cancel();fileState.Text="База паролей заблокирована. Завершаю отмену операции с файлами.";}
                else if(!TryCloseFileVault())fileState.Text="База паролей закрыта. Файловый диск остаётся открытым: завершите работу в редакторе и закройте хранилище.";
            }
            passkeyList.Items.Clear();
            // Порядок важен (ревью R-3/R-4): сначала прекращается ввод и закрываются окна
            // с секретами (их обработчики ещё видят живые данные), только затем затирание.
            // 1. Автовход отменяется: пароль не должен печататься в чужое окно после блокировки.
            if (loginCts != null) loginCts.Cancel();
            // 2. Буфер очищается ДО затирания секретов: сравнение содержимого в ClearNow
            //    должно увидеть ещё живую строку из SecureClip.
            SecureClip.ClearNow();
            // 3. Окна с секретами (ILockableDialog) закрываются до затирания; обход — по копии
            //    списка: Close() меняет Application.OpenForms во время перебора.
            foreach (var f in Application.OpenForms.Cast<Form>().ToList())
                if (f != this && f is ILockableDialog)
                    try { f.Close(); } catch { }
            // 4. Затирание ключа и секретов.
            if (vault != null) { vault.Lock(); vault = null; }
            pwList.Items.Clear();
            passwordSearch.Clear();
            // 5. След секретов в куче: сборка мусора и обнуляющая аллокация поверх освободившихся копий.
            Secure.ScrubHeap();
            lockedAt = DateTime.UtcNow;
            ShowLocked();
        }

        void Unlock()
        {
            if (unlockBusy) return;
            unlockBusy = true;
            try
            {
                if (!KdbxStore.Exists && !Vault.LegacyExists) { CreateVault(); return; }

                // Fail-closed: счётчик попыток и уничтожение требуют записи в файл. Если файл
                // недоступен для записи (носитель только для чтения, файл занят другой
                // программой) — пароль вообще не проверяется, чтобы не сжечь попытки впустую.
                if (KdbxStore.Exists && !KdbxStore.FileWritable())
                {
                    MessageBox.Show(this, "Файл базы недоступен для записи (открыт другой программой или носитель только для чтения).\n" +
                        "Проверка пароля выключена: без записи нельзя честно считать попытки.\nОсвободите файл и попробуйте снова.",
                        "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Быстрый путь: PIN. Действует, пока приложение работает; после перезапуска — полный вход.
                // Отмена или исчерпание попыток PIN — просто выход: полный вход не навязывается
                // (иначе поверх живого цикла PIN-диалогов открывались бы диалоги пароля 1).
                // Долгая блокировка гасит PIN: обёртка ключа в памяти — единственное, что защищает
                // только PIN-кодом, и не должна переживать простой (защита от анализа дампа памяти).
                if (pin != null && lockedAt != null && (DateTime.UtcNow - lockedAt.Value).TotalMinutes >= PinSessionMinutes)
                {
                    pin.Clear();
                    pin = null;
                    PwLog("PIN отключён: блокировка длится дольше " + PinSessionMinutes + " минут — вход паролем базы.");
                }
                // Windows Hello (если включён на этом ПК): жест вместо пароля. Отмена, истёкший срок или сбой — дальше
                // обычный путь (PIN или пароль базы).
                if (KdbxStore.Exists && WindowsHello.Enabled && UnlockWithHello()) return;

                if (pin != null && KdbxStore.Exists) { UnlockWithPin(); return; }

                // Миграция: старая база vault.dat (WUV1/2/3) переносится в vault.kdbx при первом полном входе.
                if (!KdbxStore.Exists && Vault.LegacyExists) { UnlockLegacy(); return; }

                int gen = lockGen;
                var v = OpenDb("База паролей");
                if (v == null) return;
                if (lockGen != gen) { v.Lock(); PwLog("Вход отменён: база заблокирована во время открытия."); return; }
                Opened(v);
                // Вход полным паролем: срок Windows Hello отсчитывается заново.
                if (WindowsHello.Enabled) ResealHello(v, "вход паролем базы");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Не удалось открыть базу:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally { unlockBusy = false; }
        }

        // Полный вход в старую базу vault.dat с немедленной миграцией в vault.kdbx (KDBX 4, Argon2).
        // Перенос сверяется поле за полем; при расхождении старый файл не трогается.
        void UnlockLegacy()
        {
            var useKf = Vault.FileUsesKeyFile();
            string kfPath = null;
            while (true)
            {
                int left = Vault.AttemptsLeft(2);
                string pw; DialogResult r;
                using (var d = new PasswordPrompt("База паролей (старый формат)", "Пароль базы:", left, Vault.P2Max,
                           Vault.FileHasRecovery() ? "Забыли пароль? Открыть кодом восстановления" : null, true, useKf))
                { r = d.ShowDialog(this); pw = d.Value; kfPath = d.KeyFile; }
                if (r == DialogResult.Retry)
                {
                    var vrc = OpenLegacyWithRecovery();
                    if (vrc == null) return;
                    if (!MigrateLegacy(vrc, null, null)) return;
                    return;
                }
                if (r != DialogResult.OK) return;
                Vault v = null; int left2 = 0; VaultResult res2;
                try { res2 = Busy(() => Vault.Open(pw, useKf ? kfPath : null, store.Settings, out v, out left2)); }
                catch (Exception ex) { MessageBox.Show(this, "Не удалось открыть базу:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
                if (res2 == VaultResult.Ok && v != null)
                {
                    if (!MigrateLegacy(v, pw, useKf ? kfPath : null)) return;
                    return;
                }
                if (res2 == VaultResult.Wiped) { Wiped(Vault.P2Max, "базы"); return; }
                MessageBox.Show(this, "Неверный пароль базы. Осталось попыток: " + left2, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // Миграция открытой старой базы в vault.kdbx со сверкой 1:1. true — успешно.
        bool MigrateLegacy(Vault legacy, string p2, string keyFilePath)
        {
            try
            {
                // Смена ключ-файла при переносе не поддерживается: база переносится с тем же составом ключа.
                if (legacy.KeyFileRequired && string.IsNullOrEmpty(keyFilePath))
                {
                    legacy.Lock();
                    MessageBox.Show(this, "Базе нужен ключ-файл — укажите его при вводе пароля базы.", "WinUp");
                    return false;
                }
                string report = "";
                int gen = lockGen;
                var migrated = Busy(() => KdbxStore.MigrateFromLegacy(legacy, p2, keyFilePath, out report));
                legacy.Lock();
                vault = migrated;
                if (lockGen != gen)
                {
                    // Пока шёл перенос, сработала блокировка (Win+L/простой): файлы дописываем
                    // до целостного состояния, но вкладку не открываем.
                    SaveVault();
                    LockVault();
                    return true;
                }
                PwLog("База перенесена в новый формат (.kdbx, Argon2). " + report +
                    " Прежний файл сохранён как vault-legacy.dat — после проверки удалите его вручную.");
                if (SaveVault())
                {
                    PwLog("Код восстановления прежней базы не переносится — создайте новый: «Код восстановления...».");
                    Opened(migrated);
                }
                else LockVault();
                return true;
            }
            catch (Exception ex)
            {
                vault = null;
                legacy.Lock(); // расшифрованные данные старой базы не оставляем в памяти
                MessageBox.Show(this, "Перенос базы не выполнен, прежний файл не изменён:\n" + ex.Message,
                    "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        Vault OpenLegacyWithRecovery()
        {
            while (true)
            {
                int left = Vault.AttemptsLeft(2);
                string code; DialogResult r;
                using (var d = new PasswordPrompt("Код восстановления", "Код:", left, Vault.P2Max, null, false))
                { r = d.ShowDialog(this); code = d.Value; }
                if (r != DialogResult.OK) return null;
                Vault v = null;
                var res = Busy(() => Vault.OpenWithRecovery(code, store.Settings, out v, out left));
                if (res == VaultResult.Wiped) { Wiped(Vault.P2Max, "базы / код восстановления"); return null; }
                if (res == VaultResult.Wrong)
                {
                    MessageBox.Show(this, "Неверный код. Осталось попыток: " + left, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    continue;
                }
                if (res != VaultResult.Ok || v == null) return null;
                // Вход кодом: сразу запросим новый пароль базы и перенесём её.
                using (var d = new SetupDialog("Новый пароль базы", store.Settings.BackupDir, false, null))
                {
                    if (d.ShowDialog(this) != DialogResult.OK) { v.Lock(); return null; }
                    if (!MigrateLegacy(v, d.DbPassword, null)) return null;
                    return null; // миграция сама открола базу
                }
            }
        }

        // Разблокировка по Windows Hello. true — база открыта; false — дальше обычный вход (отмена, срок, сбой).
        bool UnlockWithHello()
        {
            HelloResult res = HelloResult.Broken;
            int gen = lockGen;
            var hwnd = Handle;
            var key = Busy(() => { HelloResult r; var k = WindowsHello.Unseal(hwnd, "WinUp: открыть базу паролей", out r); res = r; return k; });
            if (res == HelloResult.Cancelled) { PwLog("Windows Hello: вход отменён — введите пароль базы."); return false; }
            if (res == HelloResult.Expired)
            {
                PwLog("Windows Hello: прошло " + WindowsHello.FullPasswordDays + " дней с последнего входа полным паролем — нужен пароль базы.");
                MessageBox.Show(this, "Раз в " + WindowsHello.FullPasswordDays + " дней WinUp просит полный пароль базы, чтобы вы его не забыли.\n\n" +
                    "После входа паролем Windows Hello снова будет открывать базу " + WindowsHello.FullPasswordDays + " дней.",
                    "WinUp — Windows Hello", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            if (res != HelloResult.Ok || key == null)
            {
                // Ключ Hello сменился (PIN Windows переустановлен), файл повреждён, Hello выключен в Windows.
                WindowsHello.Disable();
                PwLog("Windows Hello: открыть базу не удалось (" + res + (WindowsHello.LastError != 0 ? ", код 0x" + WindowsHello.LastError.ToString("X8") : "") +
                      ") — вход по Hello отключён, войдите паролем базы и включите его заново.");
                return false;
            }
            KdbxStore v = null;
            StoreResult sr;
            try { sr = Busy(() => KdbxStore.OpenWithKey(key, out v)); }
            finally { Array.Clear(key, 0, key.Length); }
            if (sr != StoreResult.Ok || v == null)
            {
                // Пароль базы сменили (на другом ПК или резерв восстановлен) — обёртка устарела.
                WindowsHello.Disable();
                PwLog("Windows Hello: пароль базы изменился с момента включения — вход по Hello отключён. Войдите паролем базы и включите его заново.");
                return false;
            }
            if (lockGen != gen) { v.Lock(); PwLog("Вход по Windows Hello отменён: база заблокирована."); return true; }
            Opened(v);
            var until = WindowsHello.NotAfterLocal();
            PwLog("База открыта по Windows Hello." + (until.HasValue ? " Полный пароль базы понадобится после " + until.Value.ToString("dd.MM.yyyy HH:mm") + "." : ""));
            return true;
        }

        // Обновить ключ под Windows Hello после входа полным паролем или смены пароля: новый срок FullPasswordDays.
        void ResealHello(KdbxStore v, string why)
        {
            byte[] key = null;
            try
            {
                key = v.KeyMaterial();
                WindowsHello.Seal(key, DateTime.UtcNow.AddDays(WindowsHello.FullPasswordDays));
                PwLog("Windows Hello: " + why + " — вход по Hello действует до " + WindowsHello.NotAfterLocal().Value.ToString("dd.MM.yyyy HH:mm") + ".");
            }
            catch (Exception ex)
            {
                WindowsHello.Disable();
                PwLog("Windows Hello: не удалось обновить ключ (" + ex.Message + ") — вход по Hello отключён.");
            }
            finally { if (key != null) Array.Clear(key, 0, key.Length); }
        }

        // Меню «Вход по Windows Hello...»: включить (с проверочным жестом) или отключить.
        void SetupHello()
        {
            if (WindowsHello.Enabled)
            {
                var until = WindowsHello.NotAfterLocal();
                if (MessageBox.Show(this, "Вход по Windows Hello включён на этом компьютере." +
                        (until.HasValue ? "\nПолный пароль базы понадобится после " + until.Value.ToString("dd.MM.yyyy HH:mm") + "." : "") +
                        "\n\nОтключить вход по Windows Hello?", "WinUp — Windows Hello", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                WindowsHello.Disable();
                PwLog("Windows Hello: вход отключён, ключ на этом компьютере удалён.");
                return;
            }
            var v = vault;
            if (v == null)
            {
                MessageBox.Show(this, "Сначала откройте базу паролей — Windows Hello привязывается к её ключу.", "WinUp");
                SelectTab("Пароли");
                return;
            }
            string why;
            if (!WindowsHello.Available(out why)) { MessageBox.Show(this, why, "WinUp — Windows Hello", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            if (MessageBox.Show(this, "Открывать базу паролей через Windows Hello — лицом, отпечатком или PIN-кодом Windows?\n\n" +
                    "• Ключ базы хранится зашифрованным на этом компьютере (не на флешке); расшифровать его может только Windows после вашего подтверждения.\n" +
                    "• Раз в " + WindowsHello.FullPasswordDays + " дней WinUp попросит полный пароль базы, чтобы вы его не забыли.\n" +
                    "• Сейчас Windows попросит подтвердить вход один раз — для проверки.",
                    "WinUp — Windows Hello", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            byte[] key = null;
            try
            {
                key = v.KeyMaterial();
                WindowsHello.Seal(key, DateTime.UtcNow.AddDays(WindowsHello.FullPasswordDays));
            }
            catch (Exception ex)
            {
                WindowsHello.Disable();
                MessageBox.Show(this, "Не удалось включить Windows Hello:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            finally { if (key != null) Array.Clear(key, 0, key.Length); }
            // Проверочный жест: включённым остаётся только то, что пользователь действительно может пройти.
            HelloResult res = HelloResult.Broken;
            var hwnd = Handle;
            var back = Busy(() => { HelloResult r; var k = WindowsHello.Unseal(hwnd, "WinUp: подтвердите включение входа по Windows Hello", out r); res = r; return k; });
            if (back != null) Array.Clear(back, 0, back.Length);
            if (res != HelloResult.Ok)
            {
                WindowsHello.Disable();
                MessageBox.Show(this, res == HelloResult.Cancelled ? "Подтверждение отменено — вход по Windows Hello не включён."
                    : "Windows Hello не подтвердил вход (" + res + ") — вход по Hello не включён.", "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            PwLog("Windows Hello: вход включён до " + WindowsHello.NotAfterLocal().Value.ToString("dd.MM.yyyy HH:mm") + " (дальше — полный пароль, и снова " +
                  WindowsHello.FullPasswordDays + " дней).");
            MessageBox.Show(this, "Готово: при следующем открытии базы WinUp попросит Windows Hello вместо пароля.\n\n" +
                "Если отменить окно Windows Hello, можно ввести пароль базы как обычно.", "WinUp — Windows Hello", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // Разблокировка по PIN. false — отменено или PIN отключён после ошибок (нужен полный вход).
        bool UnlockWithPin()
        {
            while (true)
            {
                string code; DialogResult r;
                using (var d = new PinPrompt(5 - pin.Fails, 5))
                { r = d.ShowDialog(this); code = d.Value; }
                if (r != DialogResult.OK) return false;
                KdbxStore v = null;
                int gen = lockGen;
                var res = Busy(() => KdbxStore.OpenWithPin(code, pin, out v));
                // Успешный вход сбрасывает счётчик ошибок: копятся неверные вводы ПОДРЯД (ревью R-6).
                if (res == StoreResult.Ok && v != null)
                {
                    if (lockGen != gen) { v.Lock(); PwLog("Вход по PIN отменён: база заблокирована."); return false; }
                    pin.Fails = 0;
                    if (vault == null) Opened(v); else v.Lock();
                    return true;
                }
                pin.Fails++;
                if (pin.Fails >= 5)
                {
                    pin.Clear();
                    pin = null;
                    MessageBox.Show(this, "Слишком много неверных PIN. Требуется полный вход паролем базы.",
                        "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
                MessageBox.Show(this, "Неверный PIN. Осталось попыток: " + (5 - pin.Fails), "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // Включение/смена/отключение PIN (меню). Требует открытой базы — PIN заворачивает её ключ.
        void ShowBrowserDialog()
        {
            using (var d = new BrowserDialog()) d.ShowDialog(this);
        }

        void SetupPin()
        {
            if (vault == null)
            {
                MessageBox.Show(this, "Сначала откройте вкладку «Пароли» — PIN привязывается к открытой базе.", "WinUp");
                SelectTab("Пароли");
                return;
            }
            if (pin == null)
            {
                using (var d = new PinSetupDialog())
                {
                    if (d.ShowDialog(this) != DialogResult.OK) return;
                    var previous = pin;
                    pin = vault.MakePin(d.Pin);
                    if (previous != null) previous.Clear();
                }
                PwLog("Включён PIN: быстрая разблокировка до перезапуска WinUp.");
                return;
            }
            var r = MessageBox.Show(this, "PIN уже задан (действует до перезапуска WinUp).\n\nДа — сменить PIN, Нет — отключить.",
                "WinUp", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (r == DialogResult.Yes)
            {
                using (var d = new PinSetupDialog())
                {
                    if (d.ShowDialog(this) != DialogResult.OK) return;
                    var previous = pin;
                    pin = vault.MakePin(d.Pin);
                    if (previous != null) previous.Clear();
                }
                PwLog("PIN изменён.");
            }
            else if (r == DialogResult.No)
            {
                pin.Clear();
                pin = null;
                PwLog("PIN отключён: разблокировка паролем базы.");
            }
        }

        // Запрос пароля базы (с переходом к коду восстановления). null — отмена или база уничтожена.
        KdbxStore OpenDb(string title)
        {
            var kfOptional = KdbxStore.KeyFileOptional();
            var useKf = KdbxStore.FileHasKeyFile() || kfOptional;
            while (true)
            {
                int left = KdbxStore.AttemptsLeft();
                string pw, kfPath = null; DialogResult r;
                using (var d = new PasswordPrompt(title, "Пароль базы:", left, KdbxStore.P2Max,
                            KdbxStore.FileHasRecovery() ? "Забыли пароль? Открыть кодом восстановления" : null, true, useKf, kfOptional))
                {
                    if (useKf) d.SetKeyFile(store.Settings.LastKeyFile);
                    r = d.ShowDialog(this);
                    pw = d.Value;
                    if (useKf) kfPath = d.KeyFile;
                }
                if (r == DialogResult.Retry) return OpenWithRecovery();
                if (r != DialogResult.OK) return null;
                KdbxStore v = null; int left2 = 0; StoreResult res = StoreResult.Wrong;
                try { v = Busy(() => KdbxStore.Open(pw, useKf ? kfPath : null, out left2, out res)); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning); continue; }
                if (res == StoreResult.Ok && v != null)
                {
                    if (v.KeyFileRequired) { store.Settings.LastKeyFile = kfPath ?? ""; SaveApps(); }
                    if (v.TabRecreated)
                        PwLog("Служебный файл tab.dat не найден (база восстановлена из резерва или перенесена одна) — создан заново: " +
                              "счётчик попыток с нуля" + (v.KeyFileRequired ? ", база открыта с ключ-файлом" : "") +
                              ". Код восстановления этой копии неизвестен — создайте новый.");
                    return v;
                }
                if (res == StoreResult.Wiped) { Wiped(KdbxStore.P2Max, "базы"); return null; }
                MessageBox.Show(this, "Неверный пароль базы. Осталось попыток: " + left2, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // Вход кодом восстановления: обязательная смена пароля базы (код — аварийный вход, ключ-файл отключается).
        KdbxStore OpenWithRecovery()
        {
            while (true)
            {
                int left = KdbxStore.AttemptsLeft();
                string code; DialogResult r;
                using (var d = new PasswordPrompt("Код восстановления", "Код:", left, KdbxStore.P2Max, null, false))
                { r = d.ShowDialog(this); code = d.Value; }
                if (r != DialogResult.OK) return null;
                KdbxStore v = null; StoreResult res = StoreResult.Wrong;
                try { v = Busy(() => KdbxStore.OpenByRecovery(code, out left, out res)); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning); continue; }
                if (res == StoreResult.Wiped) { Wiped(KdbxStore.P2Max, "базы / код восстановления"); return null; }
                if (res != StoreResult.Ok || v == null)
                {
                    MessageBox.Show(this, "Неверный код. Осталось попыток: " + left, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    continue;
                }
                using (var d = new SetupDialog("Новый пароль базы", store.Settings.BackupDir, false, null))
                {
                    if (d.ShowDialog(this) != DialogResult.OK) { v.Lock(); return null; }
                    v.SetDbPassword(d.DbPassword, null);
                    if (!SaveVaultOf(v)) { v.Lock(); LockVault(); return null; }
                    PwLog("База открыта кодом восстановления, пароль базы изменён. Ключ-файл отключён (код и есть аварийный вход).");
                }
                return v;
            }
        }

        void Opened(KdbxStore v)
        {
            vault = v;
            lockedAt = null;                 // база открыта — счётчик простоя PIN не тикает
            dbPwFails = 0; // новая открытая сессия — счётчик подтверждений заново
            PwLog("База открыта. Записей: " + vault.Entries.Count + ".");
            if (v.RecoveryNeedsRepair) PwLog("⚠ Код восстановления не удалось развернуть из служебного файла. Создайте новый код: существующая копия восстановления может быть устаревшей.");
            if (!cloudNoted)
            {
                cloudNoted = true;
                var w = CloudFolder.Warning(store.Settings.BackupDir, "Папка резерва") ?? CloudFolder.Warning(Paths.Root, "Папка WinUp");
                if (w != null) PwLog("ℹ " + w);
            }
            ShowOpen();
            RefreshPasskeys();
            if (!vault.HasRecovery && !askedRecovery)
            {
                askedRecovery = true;
                if (MessageBox.Show(this, "У базы нет кода восстановления. Без него забытый пароль базы означает потерю всех паролей.\n\nСоздать код сейчас?",
                        "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    MakeRecoveryCode(false);
            }
        }

        // Тяжёлая работа (KDF на полный вход — секунды) уходит в пул потоков, UI-поток качает
        // сообщения: окно перерисовывается, блокировка Win+L обрабатывается сразу (ревью R-1).
        // Форма на время работы отключается — повторные клики не проходят (анти-reentrancy).
        T Busy<T>(Func<T> f)
        {
            UseWaitCursor = true; Cursor.Current = Cursors.WaitCursor;
            bool wasEnabled = Enabled;
            Enabled = false;
            try
            {
                var t = System.Threading.Tasks.Task.Factory.StartNew(() => f());
                while (!t.IsCompleted) { Application.DoEvents(); System.Threading.Thread.Sleep(20); }
                if (t.IsFaulted) throw t.Exception.GetBaseException();
                return t.Result;
            }
            finally { Enabled = wasEnabled; UseWaitCursor = false; Cursor.Current = Cursors.Default; }
        }

        void Wiped(int max, string which)
        {
            ShowLocked();
            // Честный отчёт: уничтожение могло не удаться (файл занят, нет прав) — файлы придётся удалить руками.
            var fail = KdbxStore.WipeErrors.Count > 0
                ? "\n\n⚠ Не удалось уничтожить окончательно: " + string.Join("; ", KdbxStore.WipeErrors.ToArray()) + " — удалите вручную."
                : "";
            MessageBox.Show(this, "Пароль " + which + " введён неверно " + max + " раз. База паролей уничтожена." + fail +
                "\n\nВосстановление: скопируйте последний файл vault-*.kdbx из\n" + store.Settings.BackupDir + "\nв\n" + KdbxStore.KdbxFile +
                "\nОна откроется вашим паролем или кодом восстановления.",
                "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Stop);
        }

        void CreateVault()
        {
            using (var d = new SetupDialog("Новая база паролей", store.Settings.BackupDir))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    store.Settings.BackupDir = d.BackupDir;
                    store.Save();
                    int gen = lockGen;
                    vault = Busy(() => KdbxStore.Create(d.DbPassword, d.KeyFile));
                    // Создание шло секунды (Argon2): могла сработать блокировка — базу не открываем поверх замка.
                    if (lockGen != gen) { LockVault(); PwLog("База создана, но заблокирована (Win+L или простой во время создания). Откройте её заново."); return; }
                    PwLog("База создана: " + KdbxStore.KdbxFile + (d.KeyFile != null ? " + ключ-файл" : "") + BackupNote());
                    WindowsHello.Disable(); // ключ прежней базы этой папки к новой не подходит
                    ShowOpen();
                    askedRecovery = true;
                    MakeRecoveryCode(false);
                }
                catch (Exception ex) { MessageBox.Show(this, "Не удалось создать базу:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }

        // verify — спросить пароль базы (кнопка на открытой вкладке: за ПК мог сесть посторонний).
        void MakeRecoveryCode(bool verify)
        {
            if (vault == null) return;
            if (verify)
            {
                if (vault.HasRecovery && MessageBox.Show(this, "Код восстановления уже есть. Создать новый? Старый перестанет работать.",
                        "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                if (!ConfirmDbPassword("Код восстановления")) return;
            }
            var changedAt = DateTime.Now;
            bool hadCode = vault.HasRecovery;
            var code = vault.MakeRecoveryCode();
            if (!SaveVault()) { Secure.Wipe(code); return; }
            foreach (var error in KdbxStore.PurgeLocalOldCopies()) PwLog("⚠ Старая локальная копия не удалена: " + error);
            try { using (var d = new RecoveryCodeDialog(code)) d.ShowDialog(this); }
            finally { Secure.Wipe(code); }
            PwLog("Создан код восстановления." + BackupNote());
            PwLog("Копия recovery.kdbx обновляется при каждом сохранении базы.");
            if (hadCode) OfferPurgeOldBackups(changedAt, false);
        }

        int dbPwFails; // подряд неудачные подтверждения пароля базы в этой сессии (защита от подбора через диалоги)

        bool ConfirmDbPassword(string title)
        {
            // Подтверждение пароля не расходует попытки файла базы (иначе забытый пароль стирал бы её),
            // но и не должно позволять неограниченный перебор: после нескольких неудач подряд
            // операции, требующие пароль базы, блокируются до повторного открытия базы.
            if (dbPwFails >= 5)
            {
                PwLog("Слишком много неверных вводов пароля базы. Заблокируйте базу и откройте заново.");
                MessageBox.Show(this, "Слишком много неверных вводов пароля базы.\nЗаблокируйте базу и откройте её заново.", "WinUp");
                return false;
            }
            using (var p = new PasswordPrompt(title, "Текущий пароль базы:", -1, KdbxStore.P2Max))
            {
                if (p.ShowDialog(this) != DialogResult.OK) return false;
                var pw = p.Value;
                var v = vault; // снимок: Busy качает очередь, блокировка может обнулить поле между проверкой и вызовом
                try { if (Busy(() => v != null && v.VerifyDbPassword(pw))) { dbPwFails = 0; return true; } }
                finally { Secure.Wipe(pw); }
            }
            dbPwFails++;
            MessageBox.Show(this, "Неверный пароль базы.", "WinUp");
            return false;
        }

        string BackupNote()
        {
            return Backup.LastError == null ? " Резервная копия: " + store.Settings.BackupDir : "  ⚠ резервная копия не записана: " + Backup.LastError;
        }

        bool SaveVault() { return SaveVaultOf(vault); }

        bool SaveVaultOf(KdbxStore v)
        {
            try
            {
                v.Save();
                var backupErrors = new List<string>();
                Backup.Copy(KdbxStore.KdbxFile, "vault", ".kdbx", store.Settings);
                if (Backup.LastError != null) backupErrors.Add("база: " + Backup.LastError);
                if (KdbxStore.RecoveryExists) { Backup.Copy(KdbxStore.RecoveryFile, "recovery", ".kdbx", store.Settings); if (Backup.LastError != null) backupErrors.Add("восстановление: " + Backup.LastError); }
                Backup.Copy(KdbxStore.TabFile, "tab", ".dat", store.Settings);
                if (Backup.LastError != null) backupErrors.Add("служебный файл: " + Backup.LastError);
                Backup.LastError = backupErrors.Count == 0 ? null : string.Join("; ", backupErrors);
                // v может быть ещё не текущей базой (вход кодом восстановления, сброс пароля 1):
                // список записей рисуем только для открытой вкладки, иначе NRE на null vault.
                if (vault == v) RefreshEntries();
                return true;
            }
            catch (Exception ex) {
                MessageBox.Show(this, "Не удалось сохранить базу:\n" + ex.Message + "\nБазу нужно открыть заново перед дальнейшими изменениями.", "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error);
                if (v != null && v.SaveFailed && vault == v && IsHandleCreated)
                    BeginInvoke(new MethodInvoker(delegate { if (vault == v) LockVault(); }));
                return false;
            }
        }

        static string TwoFaText(LoginEntry e)
        {
            return e.TwoFa == "ask" ? "спросить" : e.TwoFa == "link" ? "из «Коды 2FA»" : "";
        }

        void RefreshEntries()
        {
            if(vault==null)return;
            RefreshPasswordCategories();
            var checkedIds = new HashSet<string>(pwList.CheckedItems.Cast<ListViewItem>().Select(i => ((LoginEntry)i.Tag).Id));
            var selId = SelectedEntry() == null ? null : SelectedEntry().Id;
            pwList.BeginUpdate(); pwList.Items.Clear();
            foreach (var e in AccountOrganization.Filter(vault.Entries,store.Templates,passwordSearch.Text,passwordCategory.SelectedIndex>0?passwordCategory.SelectedItem as string:null,passwordKind.SelectedIndex,passwordPinned.Checked).Where(e=>vault.InAccountGroup(e,passwordGroup.SelectedItem is AccountGroupInfo?((AccountGroupInfo)passwordGroup.SelectedItem).Id:null)&&(passwordTag.SelectedIndex<=0||e.Tags.Contains((string)passwordTag.SelectedItem,StringComparer.CurrentCultureIgnoreCase))))
            {
                if (e.Kind == "passkey") continue;
                var it = new ListViewItem(new[] { (e.Pinned?"★ ":"")+e.Name, e.Kind == "both" ? "приложение / сайт" : e.Kind == "app" ? "приложение" : "сайт", AccountOrganization.DisplayLogin(e), e.Target ?? "", e.Window ?? "",
                    e.AutoEnter ? "да" : "нет", TwoFaText(e), e.Kind == "app" ? "" : (string.IsNullOrEmpty(e.Browser) ? "общий" : e.Browser),AccountOrganization.Category(e,store.Templates) })
                { Tag = e, Checked = checkedIds.Contains(e.Id) };
                pwList.Items.Add(it);
                if (e.Id == selId) { it.Selected = true; it.Focused = true; }
            }
            pwList.EndUpdate();
            passwordCount.Text=pwList.Items.Count+" из "+vault.Entries.Count(e=>e.Kind!="passkey");
            if (pwList.SelectedItems.Count == 0 && pwList.Items.Count > 0) { pwList.Items[0].Selected = true; pwList.Items[0].Focused = true; }
        }

        LoginEntry SelectedEntry() { return pwList.SelectedItems.Count > 0 ? (LoginEntry)pwList.SelectedItems[0].Tag : null; }

        void AddEntry()
        {
            if (vault == null) { PwLog("База заблокирована — добавление отменено."); return; }
            var e = new LoginEntry { Id = AppStore.NewId(), AutoEnter = true };
            bool retained=false;
            using (var d = new EntryDialog(e, store, true, vault.Otp, vault.Entries,vault.AccountGroups()))
            { try {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (vault == null) { PwLog("База заблокирована во время ввода — запись не сохранена."); return; }
                vault.Otp.AddRange(d.NewOtp); // аккаунты 2FA, созданные кнопкой «Новый...», — только вместе с записью
                vault.Entries.Add(e);
                if (SaveVault()) { retained=true;RefreshOtp(); PwLog("Добавлено: " + e.Name + "." + BackupNote()); }
                else {vault.Entries.Remove(e);foreach(var o in d.NewOtp)vault.Otp.Remove(o);}
            } finally {if(!retained){e.ClearSecrets();foreach(var o in d.NewOtp)o.ClearSecret();}} }
        }

        void EditEntry() { EditEntry(SelectedEntry()); }
        void EditEntry(LoginEntry e)
        {
            if (vault == null) return;
            if (e == null || !vault.Entries.Contains(e)) return;
            var copy = e.Copy();
            bool retained = false;
            try { using (var d = new EntryDialog(copy, store, false, vault.Otp, vault.Entries,vault.AccountGroups()))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (vault == null) { PwLog("База заблокирована во время правки — изменения не сохранены."); return; }
                vault.Otp.AddRange(d.NewOtp);
                vault.Entries[vault.Entries.IndexOf(e)] = copy;
                if (SaveVault()) { retained = true; e.ClearSecrets(); RefreshOtp(); PwLog("Изменено: " + copy.Name + "."); }
                else { vault.Entries[vault.Entries.IndexOf(copy)] = e; foreach(var o in d.NewOtp) { vault.Otp.Remove(o); o.ClearSecret(); } }
            } } finally { if(!retained) copy.ClearSecrets(); }
        }

        void DeleteEntry()
        {
            var e = SelectedEntry();
            if (e == null) return;
            var current=vault;
            if (MessageBox.Show(this, "Переместить запись «" + e.Name + "» в корзину?", "WinUp", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            if (vault != current) { PwLog("База изменилась во время подтверждения — удаление отменено."); return; }
            vault.Entries.Remove(e);
            if (SaveVault()) {e.ClearSecrets();PwLog("Перемещено в корзину: " + e.Name + ".");}
        }

        void CopyField(bool login)
        {
            var e = SelectedEntry();
            if (e == null) return;
            var text = login ? e.ResolvedLogin : e.UsePassword(p=>new string((p??"").ToCharArray()));
            if (string.IsNullOrEmpty(text)) { PwLog(e.Name + ": " + (login ? "логин" : "пароль") + " не задан."); return; }
            try { SecureClip.Copy(text); }
            finally { if (!login) Secure.Wipe(text); }
            PwLog(e.Name + ": " + (login ? "логин" : "пароль") + " скопирован. Буфер очистится через 30 с.");
        }

        void CopyTotp()
        {
            var e = SelectedEntry();
            if (e == null) return;
            var o = e.TwoFa == "link" ? vault.Otp.Find(x => x.Id == e.OtpId) : null;
            if (o == null) { PwLog(e.Name + ": к записи не привязан аккаунт из вкладки «Коды 2FA» — код берите из телефона."); return; }
            SecureClip.Copy(Totp.Code(o));
            PwLog(e.Name + ": код 2FA скопирован, действует ещё " + Totp.SecondsLeftFor(o.Period) + " с.");
        }

        // Резервные копии, которые открываются прежним секретом: после смены пароля — vault-*.kdbx и tab-*.dat
        // (в tab — обёртка кода восстановления под прежним паролем), после нового кода — recovery-*.kdbx.
        // Время копии — из имени (prefix-yyyyMMdd-HHmmss-fff): File.Copy переносит дату изменения исходника.
        void OfferPurgeOldBackups(DateTime changedAt, bool password)
        {
            var dir = store.Settings.BackupDir;
            var old = new List<string>();
            try
            {
                foreach (var pe in password ? new[] { "vault|.kdbx", "tab|.dat" } : new[] { "recovery|.kdbx" })
                {
                    var prefix = pe.Split('|')[0]; var ext = pe.Split('|')[1];
                    if (!Directory.Exists(dir)) break;
                    foreach (var f in Directory.GetFiles(dir, prefix + "-*" + ext))
                    {
                        if (!string.Equals(Path.GetExtension(f), ext, StringComparison.OrdinalIgnoreCase)) continue;
                        var stamp = Path.GetFileNameWithoutExtension(f).Substring(prefix.Length + 1);
                        if (stamp.Length == 28 && stamp[19] == '-') stamp = stamp.Substring(0, 19);
                        DateTime t;
                        if (DateTime.TryParseExact(stamp, "yyyyMMdd-HHmmss-fff", System.Globalization.CultureInfo.InvariantCulture,
                                System.Globalization.DateTimeStyles.None, out t) && t < changedAt)
                            old.Add(f);
                    }
                }
            }
            catch (Exception ex) { PwLog("Старые резервные копии не проверены: " + ex.Message); return; }
            var what = password ? "прежним паролем базы" : "прежним кодом восстановления";
            if (old.Count == 0) return;
            var cloud = CloudFolder.Of(dir);
            int n10 = old.Count % 10, n100 = old.Count % 100;
            var copies = n10 == 1 && n100 != 11 ? "старая копия, которая открывается" :
                         n10 >= 2 && n10 <= 4 && (n100 < 12 || n100 > 14) ? "старые копии, которые открываются" : "старых копий, которые открываются";
            var msg = "В папке резерва " + old.Count + " " + copies + " " + what + ":\n" + dir + "\n\n" +
                      "Тот, кто знает " + (password ? "прежний пароль" : "прежний код") + ", откроет их и увидит пароли на момент копии. " +
                      "Удалить эти копии? Новые копии останутся." +
                      (cloud != null ? "\n\nПапка в " + cloud + ": удалённые файлы ещё хранятся в корзине и истории версий " + cloud + " — очистите их там вручную." : "");
            if (MessageBox.Show(this, msg, "WinUp — старые резервные копии", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            {
                PwLog("Старые резервные копии оставлены (" + old.Count + " шт., открываются " + what + "): " + dir);
                return;
            }
            int done = 0; var fails = new List<string>();
            foreach (var f in old)
            {
                string err;
                if (Secure.WipeFile(f, out err)) done++; else fails.Add(Path.GetFileName(f) + ": " + err);
            }
            PwLog("Удалено старых резервных копий: " + done + " из " + old.Count + " (" + dir + ")." +
                  (fails.Count > 0 ? " ⚠ Не удалось: " + string.Join("; ", fails.ToArray()) : "") +
                  (cloud != null ? " Папка в " + cloud + " — очистите корзину и историю версий там." : ""));
        }

        void ChangeBackupDir()
        {
            var d = Dlg.PickFolder(this, store.Settings.BackupDir);
            if (d == null) return;
            var warn = CloudFolder.Warning(d, "Папка резерва");
            if (warn != null) MessageBox.Show(this, warn, "WinUp — папка резерва", MessageBoxButtons.OK, MessageBoxIcon.Information);
            store.Settings.BackupDir = d;
            if (!SaveApps()) return;
            // База могла заблокироваться, пока был открыт выбор папки.
            if (vault != null && SaveVault()) PwLog("Папка резерва: " + d + "." + BackupNote());
        }

        void ChangePasswords()
        {
            var v = vault;
            if (v == null) return;
            if (!ConfirmDbPassword("Смена пароля базы")) return;
            using (var d = new SetupDialog("Новый пароль базы", store.Settings.BackupDir, false, v.KeyFileRequired ? store.Settings.LastKeyFile : null))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (vault == null) { PwLog("База заблокирована — пароль не изменён."); return; }
                var newKf = d.KeyFile;
                int gen = lockGen;
                var changedAt = DateTime.Now; // копии с именем раньше этого момента открываются прежним паролем
                try { Busy(() => { v.SetDbPassword(d.DbPassword, newKf); return 0; }); }
                catch (Exception ex)
                {
                    // Применить не удалось (ключ-файл удалён, диск недоступен): в памяти могла
                    // остаться половина новых учётных данных — блокируем, на диск ничего не пишем.
                    LockVault();
                    MessageBox.Show(this, "Не удалось применить новый пароль:\n" + ex.Message +
                        "\nВкладка заблокирована — на диске действует прежний пароль.",
                        "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (gen != lockGen) { LockVault(); PwLog("Пароль не изменён: база заблокирована во время смены."); return; }
                if (SaveVaultOf(v))
                {
                    PwLog("Пароль базы изменён." + (vault.KeyFileRequired ? " Ключ-файл продолжает действовать." : "") + BackupNote());
                    PwLog("Прежний пароль текущий файл больше не открывает. Код восстановления продолжает работать (recovery.kdbx обновится при сохранении).");
                    // Локальные .bak открываются СТАРЫМ паролем: vault.kdbx.bak — сама база, tab.dat.bak — обёртка кода
                    // восстановления под прежним паролем (прежний пароль → код → текущая recovery.kdbx). Затираем.
                    foreach (var error in KdbxStore.PurgeLocalOldCopies()) PwLog("⚠ Старая локальная копия не удалена: " + error);
                    OfferPurgeOldBackups(changedAt, true);
                    if (WindowsHello.Enabled) ResealHello(v, "пароль базы изменён");
                }
                else
                {
                    // Записать не удалось, а в памяти уже новые учётные данные: блокируем вкладку,
                    // чтобы следующая несвязанная правка не записала их на диск молча (ревью п.4.5).
                    LockVault();
                    MessageBox.Show(this, "Не удалось записать файл базы после смены пароля.\n" +
                        "Вкладка заблокирована. Сохранение могло завершиться частично: попробуйте новый пароль, затем прежний.\n" +
                        "При необходимости восстановите последнюю копию из папки резерва.",
                        "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        async Task LoginSelected()
        {
            var e = SelectedEntry();
            if (e == null || busyLogin) return;
            busyLogin = true;
            loginCts = new CancellationTokenSource();
            try { await Login(e, loginCts.Token); }
            catch (Exception ex) { PwLog(e.Name + ": ошибка — " + ex.Message); }
            finally { busyLogin = false; loginCts = null; SetStatus(""); }
        }

        async Task LoginChecked()
        {
            var list = pwList.CheckedItems.Cast<ListViewItem>().Select(i => (LoginEntry)i.Tag).ToList();
            if (list.Count == 0) { PwLog("Отметьте галочками записи, в которые нужно войти."); return; }
            if (busyLogin) return;
            busyLogin = true;
            loginCts = new CancellationTokenSource();
            var ct = loginCts.Token;
            try
            {
                for (int i = 0; i < list.Count; i++)
                {
                    if (ct.IsCancellationRequested) { PwLog("Ввод остановлен: база заблокирована."); break; }
                    PwLog("—— " + (i + 1) + " из " + list.Count + ": " + list[i].Name);
                    try { await Login(list[i], ct, false); }
                    catch (Exception ex) { PwLog(list[i].Name + ": ошибка — " + ex.Message); }
                    if (i + 1 < list.Count) await Task.Delay(1500);
                }
                PwLog("Готово: обработано записей — " + list.Count + ".");
            }
            finally { busyLogin = false; loginCts = null; SetStatus(""); }
        }

        bool StartTarget(LoginEntry e)
        {
            ProcessStartInfo psi;
            string where = "";
            bool openApp = e.Kind == "app";
            if (openApp)
            {
                // App selection has already checked the Windows catalog. Do not hand an
                // arbitrary protocol or command string to ShellExecute as an application.
                var catalog=LocalApplications.Scan();
                if(!catalog.IsCompleted) {PwLog(e.Name+": список приложений ещё загружается — повторите вход.");return false;}
                try {psi=LocalApplications.LaunchInfo(e.Target,e.Args,catalog.Result);}
                catch(Exception ex) {PwLog(e.Name+": "+ex.Message);return false;}
            }
            else
            {
                var name = string.IsNullOrEmpty(e.Browser) ? store.Settings.Browser : e.Browser;
                var b = Browsers.Find(name);
                if (!string.IsNullOrEmpty(name) && b == null) PwLog(e.Name + ": браузер «" + name + "» не найден на этом ПК — открываю в браузере по умолчанию.");
                psi = b != null ? new ProcessStartInfo(b.Exe, "\"" + e.Target + "\"") : new ProcessStartInfo(e.Target);
                if (b != null) where = " в " + b.Name;
            }
            psi.UseShellExecute = true;
            try { Process.Start(psi); }
            catch (Exception ex) { PwLog(e.Name + ": не удалось открыть " + e.Target + " — " + ex.Message); return false; }
            PwLog(e.Name + ": открываю " + e.Target + where);
            return true;
        }

        async Task Login(LoginEntry e, CancellationToken ct, bool replaceOutstanding = true)
        {
            if(vault==null || ct.IsCancellationRequested) return;
            bool desktop=e.Kind=="app";
            string appValue=e.Kind=="both" ? e.AppTarget : e.Target;
            if(e.Kind=="both" || desktop) {
                var apps=await LocalApplications.Available(true);
                if(vault==null || ct.IsCancellationRequested)return;
                if(!LocalApplications.Exists(appValue,apps)) {
                    var match=LocalApplications.Match(apps,e.Name,e.Kind=="both" ? e.Target : "");
                    appValue=match==null ? "" : match.Target;
                }
                if(e.Kind=="both") {
                    if(!string.IsNullOrEmpty(appValue)) {
                        var choice=MessageBox.Show(this,"Войти в приложение?\nДа — приложение, Нет — сайт.",e.Name,MessageBoxButtons.YesNoCancel,MessageBoxIcon.Question);
                        if(choice==DialogResult.Cancel)return;desktop=choice==DialogResult.Yes;
                    } else {
                        var choice=MessageBox.Show(this,"Приложение не найдено на этом ПК.\n\nДа — войти на сайт.\nНет — выбрать установленное приложение.\nОтмена — отменить вход.\n\nПосле установки WinUp повторит поиск автоматически.",e.Name,MessageBoxButtons.YesNoCancel,MessageBoxIcon.Information);
                        if(choice==DialogResult.Cancel)return;desktop=choice==DialogResult.No;
                    }
                }
                if(desktop && string.IsNullOrEmpty(appValue)) {
                    using(var picker=new LocalApplicationDialog(e.Name)) {if(picker.ShowDialog(this)!=DialogResult.OK)return;appValue=picker.Selected.Target;}
                }
            }
            if(vault==null || ct.IsCancellationRequested)return;
            if(desktop) {
                var copy=e.Copy();try {copy.Kind="app";copy.Target=appValue;if(LocalApplications.IsShell(appValue))copy.Args="";await LoginDesktop(copy,ct);}finally {copy.ClearSecrets();}
                return;
            }
            string url=BeginBrowserLogin(e,replaceOutstanding);
            var browserName=string.IsNullOrEmpty(e.Browser) ? store.Settings.Browser : e.Browser;
            var browser=Browsers.Find(browserName);
            if (!string.IsNullOrEmpty(browserName) && browser == null) { PwLog(e.Name + ": выбранный браузер не установлен. Выберите другой браузер для входа."); return; }
            var launch=BrowserPages.SiteLaunch(url, browser);
            launch.UseShellExecute=true;Process.Start(launch);
            PwLog(e.Name+": открыта отдельная вкладка входа. Старая вкладка не получает данные.");
        }

        async Task LoginDesktop(LoginEntry e, CancellationToken ct)
        {
            // База заблокирована в другом месте — секреты уже затёрты, ввод невозможен.
            if (vault == null || ct.IsCancellationRequested) return;
            if(e.UsePassword(p=>string.IsNullOrEmpty(p))) {
                if(!string.IsNullOrWhiteSpace(e.Target)) StartTarget(e);
                PwLog(e.Name+": пароль не сохранён. "+(string.IsNullOrEmpty(e.PasskeyId) ? "Сайт или приложение открыт." : "Выберите на сайте вход ключом доступа.")); return;
            }
            if (string.IsNullOrWhiteSpace(e.Window)&&e.AutoTypeRules.Count==0) { PwLog(e.Name + ": не задан заголовок окна."); return; }
            string targetReason;
            var targetBinding = DesktopTarget.Create(e.Target, out targetReason);
            if (targetBinding == null) { PwLog(e.Name + ": " + targetReason); return; }
            Func<IntPtr,bool> match=hWindow=>targetBinding.Matches(hWindow)&&ApplicationAutoType.Matches(e,Win.Title(hWindow));
            IntPtr h = Win.Windows().Where(w=>match(w.Key)).Select(w=>w.Key).FirstOrDefault();
            if (h == IntPtr.Zero && !string.IsNullOrWhiteSpace(e.Target))
            {
                if (!StartTarget(e)) return;
                var until = DateTime.Now.AddSeconds(30);
                while (h == IntPtr.Zero && DateTime.Now < until)
                {
                    await Task.Delay(300);
                    if (ct.IsCancellationRequested || vault == null) { PwLog(e.Name + ": ввод отменён — база заблокирована."); return; }
                    h = Win.Windows().Where(w=>match(w.Key)).Select(w=>w.Key).FirstOrDefault();
                }
            }
            if (h == IntPtr.Zero) { PwLog(e.Name + ": окно «" + e.Window + "» не найдено, ввод отменён."); return; }
            PwLog(e.Name + ": окно — «" + Win.Title(h) + "»");

            for (int i = e.Delay; i > 0; i--)
            {
                SetStatus(e.Name + ": ввод через " + i + " с — поставьте курсор в поле логина");
                await Task.Delay(1000);
                if (ct.IsCancellationRequested || vault == null) { PwLog(e.Name + ": ввод отменён — база заблокирована."); return; }
            }
            SetStatus("");

            // Ввод только если на переднем плане именно нужное окно — иначе пароль ушёл бы в чужое.
            if (!Win.Focus(h)) { PwLog(e.Name + ": не удалось вывести окно вперёд, ввод отменён."); return; }
            // Ещё одна проверка перед печатью секрета: блокировка могла прийти в момент отсчёта.
            if (ct.IsCancellationRequested || vault == null) { PwLog(e.Name + ": ввод отменён — база заблокирована."); return; }
            if (!targetBinding.Verify(h, out targetReason)) { PwLog(e.Name + ": " + targetReason); return; }
            string customSequence=ApplicationAutoType.SequenceFor(e,Win.Title(h));
            if(!string.IsNullOrEmpty(customSequence)){
                bool ok=await ApplicationAutoType.Run(e,vault,customSequence,h,targetBinding,ct);
                PwLog(e.Name+": "+(ok?"последовательность автоввода выполнена.":"автоввод остановлен — окно или состояние базы изменилось."));return;
            }
            // Фокус проверяется перед каждым символом: если окно потеряло передний план — ввод прерывается.
            if (!string.IsNullOrEmpty(e.ResolvedLogin))
            {
                if (!Win.TypeText(h, e.ResolvedLogin) || !Win.Key(h, Win.TAB)) { PwLog(e.Name + ": фокус ушёл из окна, ввод прерван."); return; }
            }
            if (!Win.IsForeground(h)) { PwLog(e.Name + ": фокус ушёл из окна, пароль не введён."); return; }
            if (!targetBinding.Verify(h, out targetReason)) { PwLog(e.Name + ": " + targetReason); return; }
            if (!e.UsePassword(pw => Win.TypeText(h, pw))) { PwLog(e.Name + ": фокус ушёл из окна во время ввода пароля — ввод прерван."); return; }
            if (e.AutoEnter && !Win.Key(h, Win.ENTER)) { PwLog(e.Name + ": фокус ушёл из окна, Enter не нажат."); return; }
            PwLog(e.Name + ": " + (string.IsNullOrEmpty(e.Login) ? "пароль введён" : "логин и пароль введены") + (e.AutoEnter ? ", Enter нажат." : ", Enter не нажат — войдите вручную."));

            string code = null;
            if (e.TwoFa == "ask")
            {
                using (var d = new CodeDialog(e.Name))
                {
                    if (d.ShowDialog(this) != DialogResult.OK) { PwLog(e.Name + ": ввод кода 2FA отменён."); return; }
                    code = d.Code;
                }
                if (ct.IsCancellationRequested || vault == null) { PwLog(e.Name + ": ввод отменён — база заблокирована."); return; }
            }
            else if (e.TwoFa == "link")
            {
                var otp = vault == null ? null : vault.Otp.Find(x => x.Id == e.OtpId);
                if (otp == null) { PwLog(e.Name + ": аккаунт 2FA не найден во вкладке «Коды 2FA» — введите код вручную."); return; }
                int wait = Math.Max(3, e.Delay);
                PwLog(e.Name + ": жду поле 2FA " + wait + " с...");
                await Task.Delay(wait * 1000);
                if (ct.IsCancellationRequested || vault == null) { PwLog(e.Name + ": ввод отменён — база заблокирована."); return; }
                // Код на излёте (меньше 3 с до смены) дойдёт до сайта уже устаревшим — ждём следующий.
                while (Totp.SecondsLeftFor(otp.Period) < 3)
                {
                    await Task.Delay(500);
                    if (ct.IsCancellationRequested || vault == null) { PwLog(e.Name + ": ввод отменён — база заблокирована."); return; }
                }
                code = Totp.Code(otp);
            }
            if (code == null) return;
            if (!Win.IsWindow(h)) h = Win.Find(e.Window, targetBinding.Matches);
            if (h == IntPtr.Zero || !Win.Focus(h)) { PwLog(e.Name + ": окно не на переднем плане, код 2FA не введён."); return; }
            if (!targetBinding.Verify(h, out targetReason)) { PwLog(e.Name + ": " + targetReason); return; }
            if (!Win.TypeText(h, code)) { PwLog(e.Name + ": фокус ушёл из окна, код 2FA не введён полностью."); return; }
            if (e.AutoEnter && !Win.Key(h, Win.ENTER)) { PwLog(e.Name + ": фокус ушёл из окна, Enter не нажат."); return; }
            PwLog(e.Name + ": код 2FA введён.");
        }
    }
}

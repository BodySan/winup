using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinUp
{
    // Окна, в которых набираются или видны секреты (пароли, ключи, коды): закрываются
    // при блокировке базы ДО затирания секретов. Окна без секретов (поиск установщиков,
    // мастер, «О программе») остаются открытыми — работа пользователя не теряется.
    interface ILockableDialog { }

    // Простой диалог «подпись — поле» с кнопками ОК/Отмена.
    class Dlg : Form
    {
        protected readonly TableLayoutPanel Grid;
        protected readonly Button Ok, Cancel;
        protected override void Dispose(bool disposing)
        {
            if (disposing && this is ILockableDialog) ClearInput(Controls);
            base.Dispose(disposing);
        }
        static void ClearInput(Control.ControlCollection controls)
        {
            foreach (Control control in controls)
            {
                var text = control as TextBoxBase;
                if (text != null) text.Clear();
                ClearInput(control.Controls);
            }
        }

        public static string PickFolder(IWin32Window owner, string start)
        {
            using (var d = new FolderBrowserDialog { Description = "Папка для резервных копий базы паролей", ShowNewFolderButton = true })
            {
                if (!string.IsNullOrEmpty(start) && Directory.Exists(start)) d.SelectedPath = start;
                return d.ShowDialog(owner) == DialogResult.OK ? d.SelectedPath : null;
            }
        }

        // Все диалоги WinUp (пароли, коды, генератор, код восстановления) — вне записи экрана.
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Win.ApplyCaptureProtection(this);
        }

        protected override void OnLoad(EventArgs e)
        {
            Appearance.Apply(this);
            base.OnLoad(e);
        }

        public Dlg(string title)
        {
            Text = title;
            Font = new Font("Segoe UI", 9f);
            Icon = AppIcons.Open;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(10);
            ShowInTaskbar = false;

            Grid = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill };
            Grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 400));
            Controls.Add(Grid);

            Ok = new Button { Text = "ОК", DialogResult = DialogResult.OK, AutoSize = true };
            Cancel = new Button { Text = "Отмена", DialogResult = DialogResult.Cancel, AutoSize = true };
            AcceptButton = Ok; CancelButton = Cancel;
        }

        protected Label Row(string label, Control c)
        {
            int row = Grid.RowCount++;
            var caption = new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 8, 3) };
            Grid.Controls.Add(caption, 0, row);
            c.Dock = DockStyle.Fill;
            Grid.Controls.Add(c, 1, row);
            return caption;
        }

        protected void FullRow(Control c)
        {
            int row = Grid.RowCount++;
            Grid.Controls.Add(c, 0, row);
            Grid.SetColumnSpan(c, 2);
        }

        protected Label Note(string text, Color? color = null)
        {
            var l = new Label { Text = text, AutoSize = true, MaximumSize = new Size(580, 0), Margin = new Padding(3, 6, 3, 6) };
            if (color.HasValue) l.ForeColor = color.Value;
            FullRow(l);
            return l;
        }

        protected FlowLayoutPanel Buttons(params Control[] extraLeft)
        {
            var p = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 0) };
            p.Controls.Add(Cancel); p.Controls.Add(Ok);
            foreach (var c in extraLeft) p.Controls.Add(c);
            FullRow(p);
            return p;
        }

        protected static Panel WithButton(Control main, params Control[] side)
        {
            var p = new TableLayoutPanel { ColumnCount = 1 + side.Length, AutoSize = true, Margin = Padding.Empty };
            p.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            main.Dock = DockStyle.Fill;
            p.Controls.Add(main, 0, 0);
            for (int i = 0; i < side.Length; i++)
            {
                p.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                side[i].AutoSize = true;
                p.Controls.Add(side[i], i + 1, 0);
            }
            return p;
        }

        protected bool Fail(string msg)
        {
            MessageBox.Show(this, msg, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            DialogResult = DialogResult.None;
            return false;
        }
    }

    // Ввод пароля. Если задан forgotText — ссылка «Забыли...?» закрывает диалог с DialogResult.Retry.
    class PasswordPrompt : Dlg, ILockableDialog
    {
        readonly TextBox box = new TextBox { UseSystemPasswordChar = true };
        readonly TextBox kfBox = new TextBox();
        public string Value { get { return box.Text; } }
        public string KeyFile { get { return kfBox.Text.Trim(); } }

        public PasswordPrompt(string title, string label, int attemptsLeft, int max, string forgotText = null, bool masked = true, bool keyFile = false, bool keyFileOptional = false)
            : base(title)
        {
            box.UseSystemPasswordChar = masked;
            Row(label, box);
            if (masked) Row("", new KeyboardHint());
            if (keyFile)
            {
                var browse = new Button { Text = "Обзор..." };
                browse.Click += (s, e) =>
                {
                    using (var d = new OpenFileDialog { Title = "Ключ-файл базы", Filter = "Ключ-файл (*.key;*.bin)|*.key;*.bin|Все файлы|*.*" })
                        if (d.ShowDialog(this) == DialogResult.OK) kfBox.Text = d.FileName;
                };
                Row("Ключ-файл:", WithButton(kfBox, browse));
                Note(keyFileOptional
                    ? "Служебного файла tab.dat нет (база восстановлена из резерва или перенесена одна). Если база закрыта ключ-файлом — укажите его, иначе оставьте поле пустым."
                    : "База дополнительно закрыта ключ-файлом: без него пароль базы не подходит.", SystemColors.GrayText);
            }
            // attemptsLeft < 0 — подтверждение пароля открытой базы: попытки файла не расходуются, база не уничтожается.
            if (attemptsLeft >= 0)
                Note("Осталось попыток: " + attemptsLeft + " из " + max + ". После последней неверной попытки база будет уничтожена.",
                     attemptsLeft <= 1 ? Color.Firebrick : SystemColors.GrayText);
            else
                Note("Попытки базы здесь не расходуются. После 5 неверных вводов подряд действия с паролем базы блокируются до повторного входа.",
                     SystemColors.GrayText);
            if (forgotText != null)
            {
                var forgot = new Button { Text = forgotText, AutoSize = true, Margin = new Padding(3, 0, 3, 6), DialogResult = DialogResult.Retry };
                FullRow(forgot);
            }
            Buttons();
            // Пустое поле — не попытка: случайный Enter не должен приближать уничтожение базы.
            Ok.Click += (s, e) => { if (box.Text.Length == 0) Fail("Поле «" + label.TrimEnd(':') + "» пустое."); };
        }

        public void SetKeyFile(string path) { kfBox.Text = path ?? ""; }
    }

    // Ввод PIN-кода для быстрой разблокировки (попытки файла базы не расходуются).
    class PinPrompt : Dlg, ILockableDialog
    {
        readonly TextBox box = new TextBox { UseSystemPasswordChar = true };
        public string Value { get { return box.Text; } }

        public PinPrompt(int left, int max) : base("Разблокировка по PIN")
        {
            Row("PIN-код:", box);
            Note("Осталось попыток: " + left + " из " + max + ". После " + max + " неверных PIN потребуется полный вход паролем базы.",
                 left <= 1 ? Color.Firebrick : SystemColors.GrayText);
            Buttons();
            Ok.Click += (s, e) => { if (box.Text.Length == 0) Fail("Введите PIN-код."); };
        }
    }

    // Установка/смена PIN: два поля, минимум 4 символа.
    class PinSetupDialog : Dlg, ILockableDialog
    {
        readonly TextBox a = new TextBox { UseSystemPasswordChar = true }, b = new TextBox { UseSystemPasswordChar = true };
        public string Pin { get { return a.Text; } }

        public PinSetupDialog() : base("PIN-код быстрой разблокировки")
        {
            Note("PIN открывает базу вместо пароля — удобно, когда автоблокировка срабатывает часто.\n" +
                 "Действует до перезапуска WinUp и живёт только в памяти процесса; если база стоит заблокированной\n" +
                 "дольше " + MainForm.PinSessionMinutes + " минут — PIN отключается до следующего полного входа (защита от анализа памяти).\n" +
                 "5 неверных вводов — до полного входа паролем базы. Как и у любого быстрого входа, защита слабее полного: " +
                 "не используйте PIN, совпадающий с паролем базы.");
            Row("PIN-код:", a);
            Row("Повтор PIN:", b);
            Buttons();
            Ok.Click += (s, e) =>
            {
                if (a.Text.Length < 4) { Fail("PIN — не короче 4 символов."); return; }
                if (a.Text != b.Text) { Fail("PIN и повтор не совпадают."); return; }
            };
        }
    }

    // О программе: версия и контрольный хэш exe для проверки подмены (сверяется со значением вне этого ПК).
    class AboutDialog : Dlg
    {
        public AboutDialog(string sha256, Action<string> log, bool autoCheck = false) : base("О программе")
        {
            Note("WinUp " + Application.ProductVersion + " — менеджер паролей и программ.");
            Note("База паролей — стандартный файл KDBX 4 (Argon2): открывается также в KeePassXC, KeePassDX, Strongbox.");
            Note("Хранилище и криптография — KeePassLib из KeePass " + KdbxStore.LibVersion() + ", " + CoreLoader.Source + " (© Dominik Reichl, лицензия GPL v2+, keepass.info). " +
                 "WinUp распространяется вместе с исходным кодом под GPL v3+.", SystemColors.GrayText);
            Note("Файловый модуль: Cryptomator (AGPL v3). Ключи доступа: KeePassPasskey, KeePassXC-Browser и Bouncy Castle.",SystemColors.GrayText);
            Note("WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos\nhttps://github.com/winfsp/winfsp",SystemColors.GrayText);
            var licenses=new Button { Text="Компоненты и лицензии",AutoSize=true };
            licenses.Click+=(s,e)=> {
                try {
                string folder=Path.Combine(Paths.Data,"licenses"); SafePaths.NoReparseParents(folder); Directory.CreateDirectory(folder);
                var assembly=System.Reflection.Assembly.GetExecutingAssembly();
                foreach(string name in assembly.GetManifestResourceNames().Where(n=>n.StartsWith("licenses/") || n=="THIRD-PARTY.md")) {
                    string path=Path.Combine(folder,Path.GetFileName(name));
                    SafePaths.NoReparseParents(path);
                    using(var input=ComponentResources.Open(name)) using(var output=File.Create(path)) input.CopyTo(output);
                }
                System.Diagnostics.Process.Start(folder);
                } catch(Exception ex) { MessageBox.Show(this,"Не удалось открыть лицензии: "+ex.Message,"WinUp"); }
            };
            FullRow(licenses);
            Note("Обновление крипто-ядра: сверка версии и контрольной суммы с keepass.info, проверка цифровой подписи издателя KeePass. " +
                 "Проверенное ядро применяется при перезапуске.", SystemColors.GrayText);
            Row("Папка:", new TextBox { Text = Paths.Root, ReadOnly = true });
            Note("Контрольная сумма WinUp.exe (SHA-256) — запишите её вне этого компьютера (в телефоне, на бумаге). " +
                 "Проверять подмену нужно НЕ по этому окну (подменённая программа покажет здесь что угодно), а командой Windows: " +
                 "certutil -hashfile WinUp.exe SHA256", SystemColors.GrayText);
            var box = new TextBox { Text = sha256, ReadOnly = true, Font = new Font("Consolas", 9f), Dock = DockStyle.Fill };
            FullRow(box);
            var copy = new Button { Text = "Копировать", AutoSize = true };
            copy.Click += (s, e) => SecureClip.Copy(sha256, 60);
            var upd = new Button { Text = "Проверить обновление крипто-ядра...", AutoSize = true };
            upd.Click += (s, e) => RunCoreUpdate(upd, log);
            var tools = new FlowLayoutPanel { AutoSize = true };
            tools.Controls.Add(copy);
            tools.Controls.Add(upd);
            FullRow(tools);
            Buttons();
            Ok.Text = "Закрыть";
            Cancel.Visible = false;
            if (autoCheck) Shown += (s, e) => RunCoreUpdate(upd, log);
        }

        // Проверка и обновление KeePassLib. Сеть — в фоновом потоке, диалог не замирает.
        void CoreUi(MethodInvoker action) {
            if(IsDisposed || Disposing || !IsHandleCreated)return;
            try {BeginInvoke((MethodInvoker)delegate {if(!IsDisposed && !Disposing)action();});}catch(InvalidOperationException) {}
        }
        void RunCoreUpdate(Button btn, Action<string> log)
        {
            btn.Enabled = false;
            btn.Text = "Проверяю...";
            ThreadPool.QueueUserWorkItem(delegate
            {
                string error;
                string latest = CoreUpdate.CheckLatest(out error);
                CoreUi(delegate
                {
                    if (latest == null)
                    {
                        MessageBox.Show(this, error, "WinUp — обновление крипто-ядра", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        RestoreBtn(btn);
                        return;
                    }
                    Reminder.MarkChecked(); // версия сверена с keepass.info — напоминание сбрасывается
                    string have = KdbxStore.LibVersion();
                    var prepared=ComponentInventory.Rows().First(r=>r.Id=="keepass").Pending;
                    if(prepared!=null && !CoreUpdate.IsNewer(prepared,latest)) {
                        MessageBox.Show(this,"KeePassLib "+prepared+" уже скачан и проверен.\nСейчас работает "+have+". Перезапустите WinUp, чтобы применить обновление.","WinUp — обновление крипто-ядра",MessageBoxButtons.OK,MessageBoxIcon.Information);
                        RestoreBtn(btn);return;
                    }
                    if (!CoreUpdate.IsNewer(have, latest))
                    {
                        MessageBox.Show(this, "У вас последняя версия крипто-ядра.\n\nKeePassLib " + have + ".",
                            "WinUp — обновление крипто-ядра", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        RestoreBtn(btn);
                        return;
                    }
                    if (MessageBox.Show(this, "Доступна новая версия крипто-ядра: KeePassLib " + latest +
                            " (у вас " + have + ").\n\nСкачать и подготовить обновление? Контрольная сумма будет сверена с официальной.",
                            "WinUp — обновление крипто-ядра", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                    {
                        RestoreBtn(btn);
                        return;
                    }
                    btn.Text = "Скачиваю...";
                    ThreadPool.QueueUserWorkItem(delegate
                    {
                        string error2;
                        bool ok = CoreUpdate.DownloadAndStage(latest,
                            delegate(string m) { if (log != null) CoreUi(delegate { log(m); }); },
                            out error2);
                        CoreUi(delegate
                        {
                            if (!ok)
                            {
                                MessageBox.Show(this, error2, "WinUp — обновление крипто-ядра", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                RestoreBtn(btn);
                                return;
                            }
                            if (MessageBox.Show(this, "Крипто-ядро " + latest + " скачано и проверено.\n" +
                                    "Применится при следующем запуске WinUp.\n\nПерезапустить WinUp сейчас?",
                                    "WinUp — обновление крипто-ядра", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                            {
                                CoreUpdate.RestartPendingFlag = true;
                                Close();
                            }
                            RestoreBtn(btn);
                        });
                    });
                });
            });
        }

        static void RestoreBtn(Button btn)
        {
            btn.Enabled = true;
            btn.Text = "Проверить обновление крипто-ядра...";
        }
    }

    // Создание базы и смена пароля базы.
    class KdfDialog : Dlg
    {
        readonly NumericUpDown memory;
        readonly NumericUpDown time;
        public int MemoryMiB { get { return (int)memory.Value; } }
        public int TargetMilliseconds { get { return (int)(time.Value * 1000); } }
        public KdfDialog(int currentMemory, ulong iterations) : base("Защита от подбора пароля")
        {
            Note("Сейчас: Argon2, " + currentMemory + " МБ, итераций: " + iterations + ".");
            Note("Больше памяти и времени замедляют перебор украденной копии базы. На других устройствах открытие тоже станет медленнее.");
            memory = new NumericUpDown { Minimum = Math.Max(64, currentMemory), Maximum = Math.Max(512, currentMemory), Increment = 64, Value = Math.Max(128, currentMemory) };
            time = new NumericUpDown { Minimum = 0.5M, Maximum = 5, Increment = 0.5M, DecimalPlaces = 1, Value = 1 };
            Row("Память, МБ:", memory); Row("Целевое время, секунд:", time);
            Note("Сначала измерим скорость. Текущая защита не уменьшается; результат можно отменить.");
            Buttons(); Ok.Text = "Измерить";
        }
    }

    class SetupDialog : Dlg, ILockableDialog
    {
        readonly TextBox p2 = Pw(), p2b = Pw(), backup = new TextBox(), kfPath = new TextBox();
        readonly CheckBox kfOn = new CheckBox { Text = "Ключ-файл: без него базу не открыть", AutoSize = true, MaximumSize = new Size(400, 0) };
        readonly CheckBox show = new CheckBox { Text = "Показать пароль", AutoSize = true };
        readonly Label strength = new Label { AutoSize = true, MaximumSize = new Size(400, 0), Margin = new Padding(3, 0, 3, 2), ForeColor = SystemColors.GrayText };
        public string DbPassword { get { return p2.Text; } }
        public string BackupDir { get { return backup.Text.Trim(); } }
        public string KeyFile { get { return kfOn.Checked ? kfPath.Text.Trim() : null; } }

        static TextBox Pw() { return new TextBox { UseSystemPasswordChar = true }; }

        public SetupDialog(string title, string backupDir, bool showBackup = true, string currentKeyFile = null) : base(title)
        {
            Note("Пароль базы открывает вкладку «Пароли» (или вводится PIN) и шифрует саму базу. " +
                 "После " + KdbxStore.P2Max + " неверных попыток база уничтожается. " +
                 "Если забудете его — поможет только код восстановления.");
            var phraseBtn = new Button { Text = "Придумать фразу..." };
            phraseBtn.Click += (s, e) =>
            {
                using (var g = new GenDialog(true, true))
                    if (g.ShowDialog(this) == DialogResult.OK && g.Result.Length > 0)
                    {
                        p2.Text = p2b.Text = g.Result;
                        show.Checked = true; // фразу нужно увидеть и запомнить (окно скрыто от записи экрана)
                    }
            };
            Row("Пароль базы:", WithButton(p2, phraseBtn));
            Row("Повтор пароля:", p2b);
            Row("", strength);
            Row("", new KeyboardHint());
            Row("", show);
            show.CheckedChanged += (s, e) => { p2.UseSystemPasswordChar = p2b.UseSystemPasswordChar = !show.Checked; };
            p2.TextChanged += (s, e) => { Color c; strength.Text = Strength.Describe(p2.Text, out c); strength.ForeColor = c; };
            strength.Text = "Надёжность: —";
            var kfCreate = new Button { Text = "Создать..." };
            kfCreate.Click += (s, e) =>
            {
                using (var d = new SaveFileDialog { Title = "Куда сохранить ключ-файл", FileName = "winup.key", Filter = "Ключ-файл (*.key)|*.key|Все файлы|*.*" })
                    if (d.ShowDialog(this) == DialogResult.OK)
                    {
                        var bytes = new byte[32];
                        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(bytes);
                        File.WriteAllBytes(d.FileName, bytes);
                        kfOn.Checked = true;
                        kfPath.Text = d.FileName;
                    }
            };
            var kfBrowse = new Button { Text = "Обзор..." };
            kfBrowse.Click += (s, e) =>
            {
                using (var d = new OpenFileDialog { Title = "Выбрать ключ-файл", Filter = "Ключ-файл (*.key;*.bin)|*.key;*.bin|Все файлы|*.*" })
                    if (d.ShowDialog(this) == DialogResult.OK) { kfOn.Checked = true; kfPath.Text = d.FileName; }
            };
            Row("", kfOn);
            Row("Файл:", WithButton(kfPath, kfBrowse, kfCreate));
            Note("Ключ-файл — фактор обладания: украденной базы без файла мало, потеря файла равна потере пароля базы. " +
                 "Храните его отдельно от компьютера (флешка) и сделайте копию.", SystemColors.GrayText);
            if (currentKeyFile != null) { kfPath.Text = currentKeyFile; kfOn.Checked = true; }
            backup.Text = backupDir;
            if (showBackup)
            {
                var browse = new Button { Text = "Обзор..." };
                browse.Click += (s, e) => { var d = PickFolder(this, backup.Text); if (d != null) backup.Text = d; };
                Row("Папка резерва:", WithButton(backup, browse));
                Note("Сюда после каждого изменения пишется зашифрованная копия базы. " +
                     "Лучше выбрать место вне папки WinUp: копии здесь не уничтожаются вместе с базой.", SystemColors.GrayText);
                var cloudNote = Note("", Color.DarkOrange);
                Action checkCloud = () => { var w = CloudFolder.Warning(backup.Text.Trim(), "Папка"); cloudNote.Text = w ?? ""; cloudNote.Visible = w != null; };
                backup.TextChanged += (s, e) => checkCloud();
                checkCloud();
            }
            Buttons();
            Ok.Click += (s, e) =>
            {
                if (p2.Text.Length < 8) { Fail("Пароль базы — не короче 8 символов."); return; }
                var bits = Strength.Bits(p2.Text);
                if (bits < Strength.MinForVault)
                {
                    Fail("Пароль базы слишком простой (≈ " + Math.Round(bits) + " бит, нужно от " + Strength.MinForVault + ").\n\n" +
                         "Проще всего — фраза из 5–6 слов: кнопка «Придумать фразу...». Её легко запомнить, а подобрать — нет.");
                    return;
                }
                if (p2.Text != p2b.Text) { Fail("Пароль и повтор не совпадают."); return; }
                if (kfOn.Checked)
                {
                    if (kfPath.Text.Trim().Length == 0) { Fail("Укажите файл ключа или снимите галочку."); return; }
                    if (!File.Exists(kfPath.Text.Trim())) { Fail("Файл ключа не найден: " + kfPath.Text.Trim()); return; }
                }
                if (showBackup && (BackupDir.Length == 0 || !Path.IsPathRooted(BackupDir))) { Fail("Укажите полный путь к папке резерва."); return; }
            };
        }
    }

    // Показ нового кода восстановления. Закрыть можно, только подтвердив, что код сохранён.
    class RecoveryCodeDialog : Dlg, ILockableDialog
    {
        public RecoveryCodeDialog(string code) : base("Код восстановления")
        {
            ControlBox = false;
            Note("Код восстановления открывает базу, если пароль базы забыт. " +
                 "Запишите его на бумагу или сохраните в телефоне — отдельно от этого ПК. Повторно этот код не показать: " +
                 "можно только создать новый, и тогда этот перестанет работать.");
            var box = new TextBox { Text = code, ReadOnly = true, Font = new Font("Consolas", 16f), TextAlign = HorizontalAlignment.Center };
            FullRow(box); box.Dock = DockStyle.Fill;
            var copy = new Button { Text = "Копировать", AutoSize=true };
            copy.Click += (s, e) => SecureClip.Copy(code, 60);
            var save = new Button { Text = "Сохранить в файл...", AutoSize=true };
            save.Click += (s, e) =>
            {
                using (var d = new SaveFileDialog { FileName = "WinUp — код восстановления.txt", Filter = "Текст (*.txt)|*.txt" })
                    if (d.ShowDialog(this) == DialogResult.OK)
                        File.WriteAllText(d.FileName, "Код восстановления WinUp (создан " + DateTime.Now.ToString("dd.MM.yyyy HH:mm") + "):\r\n" + code + "\r\n");
            };
            var tools = new FlowLayoutPanel { AutoSize = true };
            tools.Controls.Add(copy); tools.Controls.Add(save);
            FullRow(tools);
            var confirm = new CheckBox { Text = "Я сохранил код в надёжном месте", AutoSize = true };
            FullRow(confirm);
            Buttons();
            Cancel.Visible = false;
            Ok.Enabled = false;
            confirm.CheckedChanged += (s, e) => Ok.Enabled = confirm.Checked;
        }
    }

    // Окно ввода кода 2FA из телефона во время входа.
    class CodeDialog : Form, ILockableDialog
    {
        readonly TextBox box = new TextBox { Font = new Font("Consolas", 18f), TextAlign = HorizontalAlignment.Center, Width = 220 };
        readonly Label timerLabel = new Label { AutoSize = true, ForeColor = SystemColors.GrayText };
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 1000 };
        int seconds = 120;
        public string Code { get { return box.Text.Replace(" ", "").Trim(); } }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Win.ApplyCaptureProtection(this);
        }

        public CodeDialog(string entryName)
        {
            Text = "Код 2FA — " + entryName;
            Font = new Font("Segoe UI", 9f);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            TopMost = true;
            AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(12);
            var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Dock = DockStyle.Fill };
            flow.Controls.Add(new Label { Text = "Введите код из приложения-аутентификатора (или из SMS)\r\nи нажмите Enter — WinUp вставит его на сайт.", AutoSize = true });
            flow.Controls.Add(box);
            flow.Controls.Add(timerLabel);
            var ok = new Button { Text = "Вставить код", DialogResult = DialogResult.OK, AutoSize = true };
            var cancel = new Button { Text = "Отмена", DialogResult = DialogResult.Cancel, AutoSize = true };
            var bar = new FlowLayoutPanel { AutoSize = true };
            bar.Controls.Add(ok); bar.Controls.Add(cancel);
            flow.Controls.Add(bar);
            Controls.Add(flow);
            AcceptButton = ok; CancelButton = cancel;
            ok.Click += (s, e) => { if (Code.Length == 0) DialogResult = DialogResult.None; };
            timer.Tick += (s, e) =>
            {
                seconds--;
                timerLabel.Text = "Окно закроется через " + seconds + " с";
                if (seconds <= 0) { timer.Stop(); DialogResult = DialogResult.Cancel; Close(); }
            };
            timerLabel.Text = "Окно закроется через " + seconds + " с";
            Shown += (s, e) => { Win.Focus(Handle); Activate(); box.Focus(); timer.Start(); };
            FormClosed += (s, e) => timer.Dispose();
        }
    }

    // Генератор паролей. Настройки запоминаются до закрытия WinUp.
    // Генератор: пароль из символов (для сайтов) или фраза из слов (легко запомнить — для пароля базы).
    class GenDialog : Dlg, ILockableDialog
    {
        static int sLen = 20, sWords = 6;
        static bool sUp = true, sLow = true, sDig = true, sSym = true, sNoAmb = true, sCap = false, sWDigit = false;
        static string sSep = "-";

        readonly RadioButton modePw = new RadioButton { Text = "Пароль из символов", AutoSize = true },
                             modePhrase = new RadioButton { Text = "Фраза из слов (легко запомнить)", AutoSize = true };
        readonly NumericUpDown len = new NumericUpDown { Minimum = 8, Maximum = 64, Width = 60 };
        readonly CheckBox up = Cb("Большие буквы A–Z"), low = Cb("Маленькие буквы a–z"), dig = Cb("Цифры 0–9"),
                          sym = Cb("Спецсимволы !@#$%..."), noAmb = Cb("Без похожих символов (0/O, 1/l/I)");
        readonly NumericUpDown words = new NumericUpDown { Minimum = 4, Maximum = 10, Width = 60 };
        readonly ComboBox sep = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 140 };
        readonly CheckBox cap = Cb("Слова с заглавной буквы"), wdig = Cb("Добавить цифру");
        readonly TextBox preview = new TextBox { ReadOnly = true, Font = new Font("Consolas", 12f), Multiline = true, WordWrap = true, Height = 50 };
        readonly Label strength = new Label { AutoSize = true, Margin = new Padding(3, 0, 3, 6) };
        readonly Control pwOpts, phraseOpts;
        public string Result { get { return preview.Text; } }

        static CheckBox Cb(string t) { return new CheckBox { Text = t, AutoSize = true }; }
        static readonly string[] Seps = { "-", " ", ".", "_" }, SepNames = { "дефис (-)", "пробел", "точка (.)", "подчёркивание (_)" };

        public GenDialog(bool forEntry, bool phrase = false) : base("Генератор паролей")
        {
            Grid.ColumnStyles[1].Width = 470; // фраза из 6–10 слов: поле шире и в две строки
            len.Value = sLen; up.Checked = sUp; low.Checked = sLow; dig.Checked = sDig; sym.Checked = sSym; noAmb.Checked = sNoAmb;
            words.Value = sWords; cap.Checked = sCap; wdig.Checked = sWDigit;
            sep.Items.AddRange(SepNames); sep.SelectedIndex = Math.Max(0, Array.IndexOf(Seps, sSep));
            var modes = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true };
            modes.Controls.AddRange(new Control[] { modePw, modePhrase });
            Row("Вид:", modes);

            var p1 = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Margin = Padding.Empty };
            p1.Controls.Add(new Label { Text = "Длина:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0); p1.Controls.Add(len, 1, 0);
            var opts = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true };
            opts.Controls.AddRange(new Control[] { up, low, dig, sym, noAmb });
            p1.Controls.Add(opts, 0, 1); p1.SetColumnSpan(opts, 2);
            pwOpts = p1;

            var p2 = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Margin = Padding.Empty };
            p2.Controls.Add(new Label { Text = "Слов:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0); p2.Controls.Add(words, 1, 0);
            p2.Controls.Add(new Label { Text = "Между словами:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1); p2.Controls.Add(sep, 1, 1);
            p2.Controls.Add(cap, 0, 2); p2.SetColumnSpan(cap, 2);
            p2.Controls.Add(wdig, 0, 3); p2.SetColumnSpan(wdig, 2);
            phraseOpts = p2;

            var both = new Panel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = Padding.Empty };
            both.Controls.Add(pwOpts); both.Controls.Add(phraseOpts);
            Row("Настройки:", both);
            var again = new Button { Text = "Другой" };
            again.Click += (s, e) => Generate();
            Row("Результат:", WithButton(preview, again));
            Row("", strength);
            Note("Фраза — русские слова латиницей: набирается в любой раскладке. Для пароля базы берите 5–6 слов и больше. " +
                 "Если сайт не принимает пароль — уберите спецсимволы или уменьшите длину.", SystemColors.GrayText);
            var copy = new Button { Text = "Копировать", AutoSize = true };
            copy.Click += (s, e) => SecureClip.Copy(preview.Text);
            Buttons(copy);
            Ok.Text = forEntry ? "Использовать" : "Закрыть";
            if (!forEntry) Cancel.Visible = false;
            foreach (var c in new[] { up, low, dig, sym, noAmb, cap, wdig }) c.CheckedChanged += (s, e) => Generate();
            len.ValueChanged += (s, e) => Generate();
            words.ValueChanged += (s, e) => Generate();
            sep.SelectedIndexChanged += (s, e) => Generate();
            modePw.CheckedChanged += (s, e) => { if (modePw.Checked) Generate(); };
            modePhrase.CheckedChanged += (s, e) => { if (modePhrase.Checked) Generate(); };
            (phrase ? modePhrase : modePw).Checked = true;
            Generate();
        }

        Label error; // одна строка ошибки на окно: раньше каждое «Другой» без наборов добавляло ещё одну

        void Generate()
        {
            bool ph = modePhrase.Checked;
            pwOpts.Visible = !ph; phraseOpts.Visible = ph;
            try
            {
                double bits;
                if (ph)
                {
                    preview.Text = Passphrase.Make((int)words.Value, Seps[sep.SelectedIndex], cap.Checked, wdig.Checked);
                    bits = Passphrase.Bits((int)words.Value, wdig.Checked);
                    sWords = (int)words.Value; sSep = Seps[sep.SelectedIndex]; sCap = cap.Checked; sWDigit = wdig.Checked;
                }
                else
                {
                    preview.Text = PasswordGen.Make((int)len.Value, up.Checked, low.Checked, dig.Checked, sym.Checked, noAmb.Checked);
                    sLen = (int)len.Value; sUp = up.Checked; sLow = low.Checked; sDig = dig.Checked; sSym = sym.Checked; sNoAmb = noAmb.Checked;
                    bits = PasswordGen.Bits((int)len.Value, up.Checked, low.Checked, dig.Checked, sym.Checked, noAmb.Checked);
                }
                Color c;
                strength.Text = "Стойкость: " + Strength.Verdict(bits, out c) + " (≈ " + Math.Round(bits) + " бит)";
                strength.ForeColor = c;
                if (error != null) error.Visible = false;
            }
            catch (ArgumentException ex)
            {
                preview.Text = ""; strength.Text = "";
                if (error == null) error = Note(ex.Message, Color.Firebrick);
                error.Text = ex.Message; error.Visible = true;
            }
        }
    }

    // Портативная программа с файлами рядом: скопировать всю папку или только exe.
    // Вопрос задаётся, пока главное окно ещё активно: диалог от отключённого окна
    // мог спрятаться за ним и выглядеть как зависание.
    // Галочка удаления не предлагается для папок-контейнеров (Загрузки, Рабочий стол и т.п.).
    class FolderCopyDialog : Dlg
    {
        readonly CheckBox del = new CheckBox { AutoSize = true };
        public bool DeleteFolder { get { return del.Checked; } }

        public FolderCopyDialog(string exe, string folder, int others, bool allowDelete) : base("Портативная программа")
        {
            Note("Рядом с " + exe + " лежат другие файлы (" + others + ").\r\n" +
                 "Портативным программам обычно нужны свои файлы рядом — скопировать всю папку «" + folder + "» в WinUp?");
            if (allowDelete)
            {
                del.Text = "После копирования удалить папку «" + folder + "» из исходного места (в Корзину)";
                FullRow(del);
            }
            Buttons();
            Ok.Text = "Скопировать всю папку";
            Cancel.Text = "Только exe";
        }
    }

    // Удаление исходных файлов после копирования (когда вопроса про папку не было) — выбор на всю пачку.
    class DeleteSourcesDialog : Dlg
    {
        public DeleteSourcesDialog(int count) : base("Исходные файлы")
        {
            Note(count == 1
                ? "Файл будет скопирован в папку WinUp. Удалить его из исходного места после копирования?"
                : "Выбрано файлов: " + count + ". Внешние скопируются в папку WinUp. Удалить их из исходного места после копирования?");
            Buttons();
            Ok.Text = "Копировать, оставить";
            Cancel.Text = "Копировать и удалить";
            Cancel.DialogResult = DialogResult.Yes; // Enter — безопасное «оставить», «удалить» — только явный клик
            CancelButton = null;                    // Esc не должен удалять
        }
    }

    // Копирование в apps\: прогресс и кнопка «Отмена» (раньше окно молча отключалось
    // на всё время копирования — без прогресса и отмены это выглядело как зависание).
    class CopyProgressDialog : Form
    {
        readonly Label what = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(10, 0, 10, 0) };
        readonly ProgressBar bar = new ProgressBar { Dock = DockStyle.Bottom, Height = 22 };
        readonly Button cancel = new Button { Text = "Отмена", AutoSize = true };
        public readonly CancellationTokenSource Cts = new CancellationTokenSource();
        public bool Cancelled;
        public readonly List<string> Errors = new List<string>();

        public CopyProgressDialog()
        {
            Text = "WinUp — копирование";
            Font = new Font("Segoe UI", 9f);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            ClientSize = new Size(560, 120);
            var btns = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(4) };
            btns.Controls.Add(cancel);
            Controls.Add(what);
            Controls.Add(bar);
            Controls.Add(btns);
            cancel.Click += (s, e) => { cancel.Enabled = false; Cts.Cancel(); };
            FormClosed += (s, e) => Cts.Cancel();
        }

        public CancellationToken Token { get { return Cts.Token; } }

        public void Report(string text, int done, int total)
        {
            if (IsDisposed || !IsHandleCreated) return;
            try
            {
                BeginInvoke((Action)(() =>
                {
                    if (IsDisposed) return;
                    what.Text = text;
                    if (total > 0)
                    {
                        bar.Minimum = 0;
                        bar.Maximum = total;
                        if (done <= total) bar.Value = done;
                    }
                }));
            }
            catch (InvalidOperationException) { } // окно уже закрыто — репорт больше не нужен
        }

        public void Done()
        {
            if (IsDisposed) return;
            try { BeginInvoke((Action)(() => { if (!IsDisposed) Close(); })); } catch { }
        }
    }

    class AppDialog : Dlg
    {        readonly AppItem item;
        readonly TextBox name = new TextBox(), args = new TextBox(), note = new TextBox(),
                         desc = new TextBox { Multiline = true, Height = 70, ScrollBars = ScrollBars.Vertical };
        readonly ComboBox kind = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        readonly CheckBox admin = new CheckBox { Text = "Запускать от администратора", AutoSize = true };

        public AppDialog(AppItem a) : base("Программа")
        {
            item = a;
            name.Text = a.Name; args.Text = a.Args; note.Text = a.Note; desc.Text = a.Description;
            kind.Items.AddRange(new object[] { "Установщик", "Портативная (запуск без установки)" });
            kind.SelectedIndex = a.Kind == "portable" ? 1 : 0;
            admin.Checked = a.Admin;
            Row("Файл:", new Label { Text = a.File, AutoSize = true, Margin = new Padding(3, 7, 3, 3) });
            Row("Название:", name);
            Row("Описание:", desc);
            Row("Тип:", kind);
            var detect = new Button { Text = "Определить" };
            detect.Click += (s, e) =>
            {
                string g, n;
                Detect.Guess(Paths.Full(a.File), out g, out n);
                args.Text = g; note.Text = n;
            };
            Row("Ключи установки / параметры запуска:", WithButton(args, detect));
            Row("", admin);
            Row("Примечание:", note);
            Note("Пустые ключи — установщик откроется как обычно, с окнами. Для портативных: параметры командной строки, {root} — папка WinUp. " +
                 "Скрипты .ps1 запускаются через PowerShell, .cmd/.bat — через cmd; файл-папка открывается в Проводнике.", SystemColors.GrayText);
            Buttons();
            Ok.Click += (s, e) =>
            {
                if (name.Text.Trim().Length == 0) { Fail("Укажите название."); return; }
                item.Name = name.Text.Trim(); item.Args = args.Text.Trim(); item.Note = note.Text.Trim(); item.Description = desc.Text.Trim();
                item.Kind = kind.SelectedIndex == 1 ? "portable" : "install";
                item.Admin = admin.Checked;
            };
        }
    }

    class LinkDialog : Dlg
    {
        readonly TextBox name = new TextBox(), url = new TextBox(),
                         desc = new TextBox { Multiline = true, Height = 70, ScrollBars = ScrollBars.Vertical };

        public LinkDialog(LinkItem l) : base("Ссылка на загрузку")
        {
            name.Text = l.Name; url.Text = l.Url; desc.Text = l.Description;
            Row("Название:", name);
            Row("Сайт загрузки:", url);
            Row("Описание:", desc);
            Buttons();
            Ok.Click += (s, e) =>
            {
                var u = url.Text.Trim();
                if (name.Text.Trim().Length == 0) { Fail("Укажите название."); return; }
                if (u.Length > 0 && !u.Contains("://")) u = "https://" + u;
                Uri parsed;
                if (!Uri.TryCreate(u, UriKind.Absolute, out parsed) || (parsed.Scheme != "https" && parsed.Scheme != "http")) { Fail("Укажите адрес сайта (https://...)."); return; }
                l.Name = name.Text.Trim(); l.Url = u; l.Description = desc.Text.Trim();
            };
        }
    }

    class WindowPicker : Dlg
    {
        readonly ListBox list = new ListBox { Height = 260, IntegralHeight = false };
        public string Selected { get { return list.SelectedItem as string; } }

        public WindowPicker() : base("Открытые окна")
        {
            foreach (var w in Win.Windows().Select(w => w.Value).Distinct().OrderBy(t => t)) list.Items.Add(w);
            Note("Выберите окно. Потом можно оставить в поле только характерную часть заголовка.");
            FullRow(list); list.Dock = DockStyle.Fill;
            list.DoubleClick += (s, e) => { if (Selected != null) { DialogResult = DialogResult.OK; Close(); } };
            Buttons();
            Ok.Click += (s, e) => { if (Selected == null) Fail("Выберите окно в списке."); };
        }
    }

    // Новые файлы в apps\, которых нет в списке.
    class ScanDialog : Form
    {
        readonly ListView lv = new ListView { View = View.Details, CheckBoxes = true, FullRowSelect = true, Dock = DockStyle.Fill };
        public readonly List<AppItem> ToAdd = new List<AppItem>();
        public readonly List<string> ToIgnore = new List<string>();

        public ScanDialog(List<AppItem> found)
        {
            Text = "WinUp — новые файлы в папке apps";
            Font = new Font("Segoe UI", 9f);
            Size = new Size(820, 480);
            StartPosition = FormStartPosition.CenterParent;
            lv.Columns.Add("Файл", 330); lv.Columns.Add("Тип", 110); lv.Columns.Add("Определено", 330);
            foreach (var a in found) lv.Items.Add(new ListViewItem(new[] { a.File, KindText(a), a.Note ?? "" }) { Tag = a, Checked = true });
            var top = new Label { Dock = DockStyle.Top, Height = 58, Padding = new Padding(6), Text =
                "Эти файлы лежат в apps\\, но их нет в списке WinUp. Отметьте, что добавить. Тип и ключи подобраны автоматически — " +
                "проверьте; описание можно дописать потом в «Изменить...»." };
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(4) };
            var add = new Button { Text = "Добавить отмеченные", AutoSize = true };
            var toggle = new Button { Text = "Сменить тип у выделенных", AutoSize = true };
            var ignore = new Button { Text = "Не предлагать отмеченные", AutoSize = true };
            var later = new Button { Text = "Позже", AutoSize = true, DialogResult = DialogResult.Cancel };
            bar.Controls.AddRange(new Control[] { add, toggle, ignore, later });
            Controls.Add(lv); Controls.Add(top); Controls.Add(bar);
            CancelButton = later;

            add.Click += (s, e) => { ToAdd.AddRange(Checked()); DialogResult = DialogResult.OK; Close(); };
            ignore.Click += (s, e) =>
            {
                if (MessageBox.Show(this, "Больше не предлагать отмеченные файлы (" + Checked().Count + ")?", Text, MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                ToIgnore.AddRange(Checked().Select(a => a.File)); DialogResult = DialogResult.OK; Close();
            };
            toggle.Click += (s, e) =>
            {
                foreach (ListViewItem it in lv.SelectedItems)
                {
                    var a = (AppItem)it.Tag;
                    a.Kind = a.Kind == "portable" ? "install" : "portable";
                    // Примечание автоопределения («предлагаю как портативную») после ручной смены типа неверно.
                    if (a.Kind == "install" && string.IsNullOrEmpty(a.Args))
                        a.Note = "тип изменён вручную — ключи тихой установки задайте в «Изменить...», без них установка пойдёт с окнами";
                    else if (a.Kind == "portable") a.Note = "тип изменён вручную";
                    it.SubItems[1].Text = KindText(a);
                    it.SubItems[2].Text = a.Note;
                }
            };
        }

        List<AppItem> Checked() { return lv.CheckedItems.Cast<ListViewItem>().Select(i => (AppItem)i.Tag).ToList(); }
        static string KindText(AppItem a) { return a.Kind == "portable" ? "портативная" : "установщик"; }
    }

    class EntryDialog : Dlg, ILockableDialog
    {
        sealed class TplItem
        {
            public LoginTemplate T;
            public override string ToString() { return T == null ? "(без шаблона)" : T.Name + " — " + (T.Kind == "both" ? "приложение / сайт" : T.Kind == "app" ? "приложение" : "сайт"); }
        }

        sealed class BrItem
        {
            public string Name;
            public override string ToString() { return Name.Length == 0 ? "(как в настройках WinUp)" : Name; }
        }

        readonly LoginEntry e;
        readonly Label targetCaption;
        readonly AppStore store;
        readonly TextBox templateFilter = new TextBox();
        readonly ComboBox templateKind = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        readonly Label templateCount = new Label { AutoSize = true };
        List<LoginTemplate> templateSource;
        readonly TextBox name = new TextBox(), target = new TextBox(), args = new TextBox(), window = new TextBox(),
                         login = new TextBox(), login2 = new TextBox(), appTarget = new TextBox(), loginUrl = new TextBox(), pass = new TextBox { UseSystemPasswordChar = true },
                         notes = new TextBox();
        string loginProfile;
        List<LocalApplication> localApps = new List<LocalApplication>();
        readonly Label appState = new Label { AutoSize = true, MaximumSize = new Size(580, 0), ForeColor = SystemColors.GrayText };
        readonly Button chooseApp = new Button { Text = "Выбрать установленное…", AutoSize = true };
        int appRevision;
        readonly RadioButton site = new RadioButton { Text = "Сайт", AutoSize = true, Checked = true },
                             app = new RadioButton { Text = "Приложение", AutoSize = true },
                             both = new RadioButton { Text = "Приложение / сайт", AutoSize = true };
        readonly SecretText recovery = new SecretText();
        readonly Label recoveryInfo = new Label { AutoSize = true };
        readonly ComboBox passkeyBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        sealed class PasskeyItem {
            public LoginEntry E;
            public override string ToString() { return E == null ? "Без ключа доступа" : E.Target + " — " + E.Login; }
        }
        bool committed;
        protected override void Dispose(bool disposing) { if(disposing) {recovery.Clear();if(!committed)foreach(var o in NewOtp)o.ClearSecret();} base.Dispose(disposing); }
        readonly CheckBox enter = new CheckBox { Text = "Нажимать Enter (вход) после пароля", AutoSize = true },
                          show = new CheckBox { Text = "Показать", AutoSize = true };
        readonly List<OtpEntry> otps;
        // Аккаунты 2FA, созданные кнопкой «Новый...»: попадают в базу только по ОК записи (MainForm добавляет их
        // вместе с ней). Раньше они сразу уходили в список базы и при «Отмене» молча сохранялись следующей правкой.
        public readonly List<OtpEntry> NewOtp = new List<OtpEntry>();
        readonly ComboBox otpBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        readonly Button otpAdd = new Button { Text = "Новый..." };
        readonly ComboBox twofa = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList },
                          browser = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList },
                          tpl = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, MaxDropDownItems = 25 };
        readonly NumericUpDown delay = new NumericUpDown { Minimum = 0, Maximum = 60, Width = 60 };
        readonly Button browse = new Button { Text = "Обзор..." };

        sealed class OtpItem
        {
            public OtpEntry O;
            public override string ToString() { return O.Title; }
        }

        public EntryDialog(LoginEntry entry, AppStore store, bool isNew, List<OtpEntry> otps, IEnumerable<LoginEntry> passkeys = null) : base(isNew ? "Новая запись для входа" : "Запись для входа")
        {
            e = entry; this.store = store; this.otps = otps;
            AutoSize = false; ClientSize = new Size(650, Math.Min(760, Screen.FromControl(this).WorkingArea.Height - 100));
            Controls.Remove(Grid); Grid.Dock = DockStyle.Top;
            var scroll = new Panel { AutoScroll = true, Dock = DockStyle.Fill }; scroll.Controls.Add(Grid); Controls.Add(scroll);

            if (isNew)
            {
                templateSource = store.Templates.OrderBy(t => t.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
                Row("Поиск шаблона:", templateFilter);
                templateKind.Items.AddRange(new object[] { "Все типы", "Сайты", "Приложения", "Приложение / сайт" }); templateKind.SelectedIndex=0;
                Row("Тип шаблона:", templateKind);
                Row("Шаблон:", tpl);
                Row("Найдено:", templateCount);
                templateFilter.TextChanged += (s,a) => FilterTemplates(); templateKind.SelectedIndexChanged += (s,a) => FilterTemplates();
                tpl.SelectedIndexChanged += (s, a) => { var item=tpl.SelectedItem as TplItem; if(item!=null) ApplyTemplate(item.T); };
                FilterTemplates();
            }

            var kinds = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty };
            kinds.Controls.Add(site); kinds.Controls.Add(app); kinds.Controls.Add(both);
            Row("Название:", name);
            Row("Тип:", kinds);
            targetCaption=Row("Адрес сайта:", WithButton(target, browse));
            Row("Адрес страницы входа:", loginUrl);
            Note("Для сайта вход выполняет расширение в отдельной вкладке. Пустой адрес входа — правила шаблона или адрес сайта. Внешний сервис входа должен быть предусмотрен шаблоном.",SystemColors.GrayText);
            var browseApp = new Button { Text = "Обзор..." };
            Row("Путь к приложению:", WithButton(appTarget, browseApp));
            Row("Приложение на этом ПК:", chooseApp);
            FullRow(appState);
            Row("Параметры запуска:", args);
            browser.Items.Add(new BrItem { Name = "" });
            foreach (var b in Browsers.Installed()) browser.Items.Add(new BrItem { Name = b.Name });
            Row("Браузер:", browser);
            var pick = new Button { Text = "Выбрать из открытых..." };
            Row("Заголовок окна:", WithButton(window, pick));
            Note("Заголовок окна нужен только для ввода в приложение. Несколько вариантов — через |.", SystemColors.GrayText);
            Row("Логин:", login);
            Row("Доп. логин / почта / телефон:", login2);
            var gen = new Button { Text = "Сгенерировать..." };
            Row("Пароль:", WithButton(pass, show, gen));
            Row("", enter);
            twofa.Items.AddRange(new object[] { "Нет", "Спросить код при входе (ввести из телефона / SMS)", "Взять код из вкладки «2FA»" });
            Row("Код 2FA:", twofa);
            foreach (var o in otps.OrderBy(x => x.Title, StringComparer.CurrentCultureIgnoreCase)) otpBox.Items.Add(new OtpItem { O = o });
            Row("Аккаунт 2FA:", WithButton(otpBox, otpAdd));
            Note("«Спросить код» — после пароля появится окошко, впишите код из телефона. «Из вкладки „2FA“» — WinUp сам вставит код; " +
                 "аккаунт берётся из вкладки «2FA» (или нажмите «Новый...»).", SystemColors.GrayText);
            Row("Пауза перед вводом, с:", delay);
            passkeyBox.Items.Add(new PasskeyItem());
            foreach(var key in (passkeys ?? new LoginEntry[0]).Where(x => x.Kind == "passkey").OrderBy(x => x.Target)) passkeyBox.Items.Add(new PasskeyItem { E = key });
            Row("Ключ доступа:", passkeyBox);
            var editCodes = new Button { Text = "Изменить / показать..." };
            Row("Резервные коды:", WithButton(recoveryInfo, editCodes));
            Row("Заметка:", notes);
            var saveTpl = new Button { Text = "Сохранить как шаблон", AutoSize = true };
            var entryButtons=Buttons(saveTpl);Grid.Controls.Remove(entryButtons);entryButtons.Dock=DockStyle.Bottom;Controls.Add(entryButtons);scroll.BringToFront();

            FillFrom(e);

            chooseApp.Click += async (s,a) => {
                using(var d = new LocalApplicationDialog(name.Text)) {
                    if(d.ShowDialog(this)==DialogResult.OK && !IsDisposed) {
                        if(app.Checked)target.Text=d.Selected.Target;else appTarget.Text=d.Selected.Target;
                        if(LocalApplications.IsShell(d.Selected.Target))args.Text="";
                        localApps=await LocalApplications.Available();
                        if(!IsDisposed)UpdateAppStatus();
                    }
                }
            };
            name.TextChanged += (s,a) => {appRevision++;};
            target.TextChanged += (s,a) => {appRevision++;UpdateAppStatus();};
            appTarget.TextChanged += (s,a) => {appRevision++;UpdateAppStatus();};
            Shown += async (s,a) => await FindApplication();

            show.CheckedChanged += (s, a) => pass.UseSystemPasswordChar = !show.Checked;
            EventHandler kindChanged=async (s,a)=>{UpdateKind();if(((RadioButton)s).Checked && IsHandleCreated)await FindApplication();};
            site.CheckedChanged += kindChanged;
            app.CheckedChanged += kindChanged; both.CheckedChanged += kindChanged;
            browseApp.Click += (s, a) => { using(var d = new OpenFileDialog { Filter = "Программы (*.exe;*.lnk)|*.exe;*.lnk|Все файлы|*.*" }) if(d.ShowDialog(this) == DialogResult.OK) appTarget.Text = Paths.Rel(d.FileName); };
            editCodes.Click += (s, a) => recovery.Use(codes => { using(var d = new RecoveryCodesDialog(codes)) if(d.ShowDialog(this) == DialogResult.OK) { var value = d.Value; try { recovery.Set(value); UpdateCodesInfo(); } finally { Secure.Wipe(value); } } return 0; });
            twofa.SelectedIndexChanged += (s, a) => otpBox.Enabled = otpAdd.Enabled = twofa.SelectedIndex == 2;
            otpAdd.Click += (s, a) =>
            {
                var o = new OtpEntry { Id = AppStore.NewId(), Issuer = name.Text.Trim(), Account = login.Text.Trim() };
                using (var d = new OtpDialog(o, true))
                    if (d.ShowDialog(this) == DialogResult.OK)
                    {
                        NewOtp.Add(o);
                        var item = new OtpItem { O = o };
                        otpBox.Items.Add(item); otpBox.SelectedItem = item;
                    }
            };
            browse.Click += (s, a) =>
            {
                using (var d = new OpenFileDialog { Filter = "Программы (*.exe;*.lnk)|*.exe;*.lnk|Все файлы|*.*" })
                    if (d.ShowDialog(this) == DialogResult.OK) target.Text = Paths.Rel(d.FileName);
            };
            pick.Click += (s, a) =>
            {
                using (var d = new WindowPicker())
                    if (d.ShowDialog(this) == DialogResult.OK) window.Text = d.Selected;
            };
            gen.Click += (s, a) =>
            {
                using (var d = new GenDialog(true))
                    if (d.ShowDialog(this) == DialogResult.OK && d.Result.Length > 0) { pass.Text = d.Result; show.Checked = true; }
            };
            saveTpl.Click += (s, a) => SaveAsTemplate();
            Ok.Click += (s, a) => Commit();
        }

        void FillFrom(LoginEntry x)
        {
            name.Text = x.Name; target.Text = x.Target; appTarget.Text = x.AppTarget; loginUrl.Text=x.LoginUrl;loginProfile=x.LoginProfile;args.Text = x.Args; window.Text = x.Window; login.Text = x.Login; login2.Text = x.Login2;
            x.UseRecoveryCodes(c => { recovery.Set(c); return 0; }); UpdateCodesInfo();
            passkeyBox.SelectedItem = passkeyBox.Items.Cast<PasskeyItem>().FirstOrDefault(i => i.E != null && i.E.Id == x.PasskeyId) ?? passkeyBox.Items[0];
            x.UsePassword(pw => { var handle = pass.Handle; pass.Text = pw; return 0; }); notes.Text = x.Notes;
            enter.Checked = x.AutoEnter; delay.Value = Math.Max(0, Math.Min(60, x.Delay));
            app.Checked = x.Kind == "app"; both.Checked = x.Kind == "both"; site.Checked = !app.Checked && !both.Checked;
            twofa.SelectedIndex = x.TwoFa == "ask" ? 1 : x.TwoFa == "link" ? 2 : 0;
            otpBox.SelectedItem = otpBox.Items.Cast<OtpItem>().FirstOrDefault(i => i.O.Id == x.OtpId);
            otpBox.Enabled = otpAdd.Enabled = twofa.SelectedIndex == 2;
            SelectBrowser(x.Browser ?? "");
            UpdateKind();
        }

        void SelectBrowser(string n)
        {
            var item = browser.Items.Cast<BrItem>().FirstOrDefault(b => b.Name == n);
            if (item == null) { item = new BrItem { Name = n }; browser.Items.Add(item); } // браузера нет на этом ПК
            browser.SelectedItem = item;
        }
        void FilterTemplates() {
            string query=templateFilter.Text.Trim(), kind=templateKind.SelectedIndex==1 ? "site" : templateKind.SelectedIndex==2 ? "app" : templateKind.SelectedIndex==3 ? "both" : null;
            var found=templateSource.Where(t => (kind==null || t.Kind==kind) &&
                ((t.Name ?? "").IndexOf(query,StringComparison.CurrentCultureIgnoreCase)>=0 || (t.Target ?? "").IndexOf(query,StringComparison.CurrentCultureIgnoreCase)>=0 || (t.Group ?? "").IndexOf(query,StringComparison.CurrentCultureIgnoreCase)>=0)).ToList();
            tpl.BeginUpdate(); tpl.Items.Clear(); tpl.Items.Add(new TplItem()); foreach(var t in found) tpl.Items.Add(new TplItem { T=t }); tpl.SelectedIndex=0; tpl.EndUpdate();
            templateCount.Text=found.Count+" из "+templateSource.Count;
        }

        void ApplyTemplate(LoginTemplate t)
        {
            if (t == null) return;
            name.Text = t.Name; app.Checked = t.Kind == "app"; both.Checked = t.Kind == "both"; site.Checked = !app.Checked && !both.Checked;
            target.Text = t.Target; appTarget.Text = t.AppTarget; loginUrl.Text=t.LoginUrl;loginProfile=t.LoginProfile;args.Text = t.Args; window.Text = t.Window; enter.Checked = t.AutoEnter;
            twofa.SelectedIndex = t.TwoFa == "ask" ? 1 : t.TwoFa == "link" ? 2 : 0;
            notes.Text = t.Note;
            UpdateKind();
            if(IsHandleCreated) { var ignored=FindApplication(); }
            login.Focus();
        }

        void UpdateKind()
        {
            targetCaption.Text=app.Checked ? "Файл программы:" : "Адрес сайта:";
            browse.Enabled = app.Checked; args.Enabled = app.Checked || both.Checked;
            appTarget.Parent.Enabled = both.Checked; browser.Enabled = !app.Checked;
            loginUrl.Enabled=!app.Checked;window.Parent.Enabled=app.Checked || both.Checked;
            chooseApp.Enabled=app.Checked || both.Checked;
            appRevision++;UpdateAppStatus();
        }
        async Task FindApplication() {
            if(site.Checked) {UpdateAppStatus();return;}
            int revision=appRevision;appState.Text="Ищу установленные приложения Windows…";
            var found=await LocalApplications.Available(true);
            if(IsDisposed || Disposing || revision!=appRevision)return;
            localApps=found;
            var box=app.Checked ? target : appTarget;
            if(!LocalApplications.Exists(box.Text,found)) {
                var match=LocalApplications.Match(found,name.Text,app.Checked ? "" : target.Text);
                if(match!=null) {box.Text=match.Target;if(LocalApplications.IsShell(match.Target))args.Text="";}
            }
            UpdateAppStatus();
        }
        void UpdateAppStatus() {
            if(site.Checked) {appState.Text="Вход на сайт выполняется через браузер. Приложение не требуется.";return;}
            string value=app.Checked ? target.Text : appTarget.Text;
            args.Enabled=!LocalApplications.IsShell(value);
            bool exists=LocalApplications.Exists(value,localApps);
            appState.Text=exists ? "Приложение найдено на этом ПК."+(LocalApplications.IsShell(value) ? " Windows запускает его по постоянному идентификатору; параметры запуска не используются." : "") :
                (both.Checked ? "Приложение пока не найдено. Запись можно сохранить и входить на сайт. После установки WinUp повторит поиск; другой путь задайте через «Выбрать установленное…» или «Обзор…»." : "Выберите установленное приложение или файл .exe / .lnk. Запись можно сохранить до установки.");
            appState.ForeColor=exists ? SystemColors.GrayText : Color.DarkGoldenrod;
        }
        void UpdateCodesInfo() { recoveryInfo.Text = recovery.Use(c => string.IsNullOrWhiteSpace(c) ? "Не добавлены" : "Сохранены в защищённом поле"); }

        void SaveAsTemplate()
        {
            if (name.Text.Trim().Length == 0) { Fail("Для шаблона нужно название."); return; }
            var t = new LoginTemplate
            {
                Name = name.Text.Trim(), Group = "Мои", Kind = app.Checked ? "app" : both.Checked ? "both" : "site", Target = target.Text.Trim(), AppTarget = appTarget.Text.Trim(), Args = args.Text.Trim(),
                LoginUrl=loginUrl.Text.Trim(),LoginProfile=loginProfile,
                // Заметка записи — личное (её видно только в зашифрованной базе), а шаблоны лежат в apps.json
                // открытым текстом: в шаблон не копируется.
                Window = window.Text.Trim(), AutoEnter = enter.Checked, TwoFa = TwoFaValue() == "link" ? "ask" : TwoFaValue(), Note = ""
            };
            store.Templates.RemoveAll(x => x.Group == "Мои" && x.Name == t.Name);
            store.Templates.Add(t);
            try { store.Save(); MessageBox.Show(this, "Шаблон «" + t.Name + "» сохранён (группа «Мои»). Логин, пароль и заметка в шаблон не попадают.", Text); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); }
        }

        string TwoFaValue() { return twofa.SelectedIndex == 1 ? "ask" : twofa.SelectedIndex == 2 ? "link" : "none"; }

        void Commit()
        {
            if (name.Text.Trim().Length == 0) { Fail("Укажите название."); return; }
            var t = target.Text.Trim();
            if(app.Checked && window.Text.Trim().Length == 0) { Fail("Для ввода в приложение укажите заголовок его окна."); return; }
            if(!app.Checked && t.Length > 0) { if(!t.Contains("://")) t="https://"+t; Uri uri; if(!Uri.TryCreate(t,UriKind.Absolute,out uri) || (uri.Scheme!="https" && uri.Scheme!="http") || uri.UserInfo.Length>0) { Fail("Укажите адрес сайта http:// или https:// без логина в адресе."); return; } }
            if(!app.Checked && loginUrl.Text.Trim().Length>0 && LoginProfiles.Resolve(new LoginEntry {Target=t,LoginUrl=loginUrl.Text.Trim(),LoginProfile=loginProfile})==null) { Fail("Адрес входа должен быть HTTPS и принадлежать сайту записи или проверенному сервису входа её шаблона.");return; }
            var key = (passkeyBox.SelectedItem as PasskeyItem).E;
            if(key != null && (app.Checked || !SiteDomain.SameSite(SiteDomain.HostOf(t), key.Target))) { Fail("Ключ доступа должен принадлежать сайту этой записи."); return; }
            string appValue=app.Checked ? t : both.Checked ? appTarget.Text.Trim() : "";
            if(LocalApplications.IsShell(appValue) && !string.IsNullOrWhiteSpace(args.Text)) {Fail("Для запуска через список приложений Windows параметры не поддерживаются. Очистите параметры запуска или выберите .exe через «Обзор…».");return;}
            if (app.Checked && t.Length > 0 && !LocalApplications.Exists(t,localApps) &&
                MessageBox.Show(this, "Программа не найдена на этом ПК:\n" + Paths.Full(t) + "\n\nСохранить всё равно (например, установите её позже)?",
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            { DialogResult = DialogResult.None; return; }
            var mode = TwoFaValue();
            var otp = otpBox.SelectedItem as OtpItem;
            if (mode == "link" && otp == null) { Fail("Выберите аккаунт 2FA или нажмите «Новый...»."); return; }

            e.Name = name.Text.Trim(); e.Kind = app.Checked ? "app" : both.Checked ? "both" : "site";
            if (site.Checked && t.Length > 0 && !t.Contains("://")) t = "https://" + t;
            e.Target = t; e.AppTarget = both.Checked ? appTarget.Text.Trim() : ""; e.Args = app.Checked || both.Checked ? args.Text.Trim() : "";
            e.LoginUrl=app.Checked ? null : loginUrl.Text.Trim();e.LoginProfile=app.Checked ? null : loginProfile;
            e.Browser = !app.Checked ? ((BrItem)browser.SelectedItem).Name : "";
            e.Window = window.Text.Trim(); e.Login = login.Text; e.Login2 = login2.Text; e.Password = pass.Text;
            e.PasskeyId = key == null ? null : key.Id; recovery.Use(c => { e.RecoveryCodes = c; return 0; });
            e.AutoEnter = enter.Checked; e.TwoFa = mode; e.OtpId = mode == "link" ? otp.O.Id : null; e.Totp = ""; e.AutoTotp = false;
            e.Delay = (int)delay.Value; e.Notes = notes.Text;
            committed=true;
        }
    }
    sealed class RecoveryCodesDialog : Dlg, ILockableDialog {
        readonly TextBox codes = new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, Height = 180, MaxLength = 32768 };
        public string Value { get { return codes.Text; } }
        public RecoveryCodesDialog(string value) : base("Резервные коды аккаунта") {
            Note("Вставьте коды восстановления, по одному на строку. Использованный код можно удалить здесь. Расширение не получает эти коды.");
            Row("Коды:", codes); Buttons(); var handle = codes.Handle; codes.Text = value;
        }
    }
}

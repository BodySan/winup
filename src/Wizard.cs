using System;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinUp
{
    // Показ сгенерированного ключа экспорта: копировать, сохранить, закрыть после подтверждения.
    class KeyDialog : Dlg, ILockableDialog
    {
        public KeyDialog(string title, string text, string key, string fileName) : base(title)
        {
            ControlBox = false;
            Note(text);
            var box = new TextBox { Text = key, ReadOnly = true, Font = new Font("Consolas", 14f), TextAlign = HorizontalAlignment.Center };
            FullRow(box); box.Dock = DockStyle.Fill;
            var copy = new Button { Text = "Копировать", AutoSize = true };
            copy.Click += (s, e) => SecureClip.Copy(key, 60);
            var save = new Button { Text = "Сохранить в файл...", AutoSize = true };
            save.Click += (s, e) =>
            {
                using (var d = new SaveFileDialog { FileName = fileName, Filter = "Текст (*.txt)|*.txt" })
                    if (d.ShowDialog(this) == DialogResult.OK) File.WriteAllText(d.FileName, title + ":\r\n" + key + "\r\n");
            };
            var tools = new FlowLayoutPanel { AutoSize = true };
            tools.Controls.Add(copy); tools.Controls.Add(save);
            FullRow(tools);
            var confirm = new CheckBox { Text = "Я сохранил ключ", AutoSize = true };
            FullRow(confirm);
            Buttons();
            Cancel.Visible = false;
            Ok.Enabled = false;
            confirm.CheckedChanged += (s, e) => Ok.Enabled = confirm.Checked;
        }
    }

    class ExportDialog : Dlg, ILockableDialog
    {
        readonly CheckBox kdbx = new CheckBox { Text = "Копия базы (.kdbx) — открывается в KeePassXC и на телефоне (KeePassDX / Strongbox) вашим паролем базы", AutoSize = true, Checked = true },
                          zip = new CheckBox { Text = "Архив .zip с шифрованием AES-256 — внутри таблица и текстовый файл; открывается в 7-Zip или WinRAR", AutoSize = true },
                          csv = new CheckBox { Text = "CSV — для переноса паролей в другие менеджеры (без шифрования)", AutoSize = true },
                          show = new CheckBox { Text = "Показать", AutoSize = true };
        readonly TextBox folder = new TextBox(), own = new TextBox { UseSystemPasswordChar = true, Enabled = false };
        readonly RadioButton gen = new RadioButton { Text = "Сгенерировать надёжный ключ (рекомендуется)", AutoSize = true, Checked = true },
                             mine = new RadioButton { Text = "Свой ключ:", AutoSize = true };

        public bool Kdbx { get { return kdbx.Checked; } }
        public bool Zip { get { return zip.Checked; } }
        public bool Csv { get { return csv.Checked; } }
        public string Folder { get { return folder.Text.Trim(); } }
        public string OwnKey { get { return Zip && mine.Checked ? own.Text : null; } }

        public ExportDialog() : base("Экспорт паролей")
        {
            Note("Сохраните копию базы, зашифрованный архив или CSV для переноса паролей в другой менеджер.");
            var formats = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true };
            foreach (var format in new[] { kdbx, zip, csv })
            {
                format.AutoSize = false;
                format.Width = 390;
                format.Height = TextRenderer.MeasureText(format.Text, Font, new Size(365, int.MaxValue), TextFormatFlags.WordBreak).Height + 6;
            }
            formats.Controls.Add(kdbx); formats.Controls.Add(zip); formats.Controls.Add(csv);
            Row("Что создать:", formats);
            var csvNote = Note("CSV содержит адреса сайтов, логины, пароли, заметки и связанные секреты 2FA. " +
                 "Менеджер получателя может принять только часть полей. Ключи доступа, записи без пароля или адреса сайта, " +
                 "дополнительные логины и поля через CSV не переносятся. " +
                 "Пароли в CSV открыты: импортируйте файл в нужный менеджер и удалите его. Не открывайте CSV для переноса в Excel.", SystemColors.GrayText);
            csvNote.Visible = false;
            csv.CheckedChanged += (s, e) => csvNote.Visible = csv.Checked;
            folder.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WinUp — экспорт");
            var browse = new Button { Text = "Обзор..." };
            browse.Click += (s, e) =>
            {
                using (var d = new FolderBrowserDialog { Description = "Куда сохранить экспорт", ShowNewFolderButton = true })
                    if (d.ShowDialog(this) == DialogResult.OK) folder.Text = d.SelectedPath;
            };
            Row("Папка:", WithButton(folder, browse));
            var keys = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true };
            keys.Controls.Add(gen); keys.Controls.Add(mine);
            var keyCaption = Row("Ключ архива .zip:", keys);
            var keyValue = WithButton(own, show);
            Row("", keyValue);
            var zipNote = Note("Ключ нужен только архиву .zip. Сгенерированный ключ покажется один раз — запишите его и не храните рядом с файлами. " +
                 "Архив .zip не откроется стандартным Проводником Windows — нужен 7-Zip или WinRAR. " +
                 "После распаковки .zip пароли лежат открытым текстом — удаляйте распакованные файлы.", SystemColors.GrayText);
            Buttons();
            Ok.Text = "Создать";
            mine.CheckedChanged += (s, e) => UpdateKeyState();
            Action showZip = () => { keyCaption.Visible = keys.Visible = keyValue.Visible = zipNote.Visible = zip.Checked; };
            zip.CheckedChanged += (s, e) => { UpdateKeyState(); showZip(); };
            UpdateKeyState();
            showZip();
            show.CheckedChanged += (s, e) => own.UseSystemPasswordChar = !show.Checked;
            Ok.Click += (s, e) =>
            {
                if (!kdbx.Checked && !zip.Checked && !csv.Checked) { Fail("Отметьте хотя бы один формат."); return; }
                if (Folder.Length == 0 || !Path.IsPathRooted(Folder)) { Fail("Укажите папку."); return; }
                if (zip.Checked && mine.Checked) { var p = Export.KeyProblem(own.Text); if (p != null) { Fail(p); return; } }
            };
        }

        void UpdateKeyState()
        {
            gen.Enabled = mine.Enabled = zip.Checked;
            own.Enabled = show.Enabled = zip.Checked && mine.Checked;
        }
    }

    // Мастер первого запуска: приветствие → найти установщики → база паролей → где что находится.
    class WizardForm : Form
    {
        readonly Label title = new Label { Dock = DockStyle.Top, Height = 40, Font = new Font("Segoe UI", 14f, FontStyle.Bold), Padding = new Padding(4, 6, 0, 0) };
        readonly Label body = new Label { Dock = DockStyle.Top, Height = 230, Font = new Font("Segoe UI", 10f), Padding = new Padding(6) };
        readonly Button action = new Button { AutoSize = true, Font = new Font("Segoe UI", 10f), Padding = new Padding(8, 4, 8, 4) };
        readonly Label result = new Label { AutoSize = true, Font = new Font("Segoe UI", 10f), ForeColor = Color.DarkGreen, MaximumSize = new Size(600, 0) };
        readonly Button back = new Button { Text = "Назад", AutoSize = true }, next = new Button { Text = "Далее", AutoSize = true },
                        skip = new Button { Text = "Пропустить мастер", AutoSize = true, DialogResult = DialogResult.Cancel };
        readonly Label stepLabel = new Label { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(3, 8, 20, 3) };
        readonly Func<Task<int>> findInstallers;
        readonly Func<bool> createVault;
        readonly Action openHelp;
        bool hasVault;
        int step;

        public WizardForm(Func<Task<int>> findInstallers, Func<bool> createVault, Action openHelp, bool hasVault)
        {
            this.findInstallers = findInstallers; this.createVault = createVault; this.openHelp = openHelp; this.hasVault = hasVault;
            Text = "WinUp — первый запуск";
            Font = new Font("Segoe UI", 9f);
            Size = new Size(680, 470);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            Padding = new Padding(16);

            var actionPanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 90, FlowDirection = FlowDirection.TopDown, Padding = new Padding(4) };
            actionPanel.Controls.Add(action); actionPanel.Controls.Add(result);
            var nav = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
            nav.Controls.AddRange(new Control[] { stepLabel, back, next, skip });
            Controls.Add(actionPanel); Controls.Add(body); Controls.Add(title); Controls.Add(nav);
            CancelButton = skip;

            back.Click += (s, e) => ShowStep(step - 1);
            next.Click += (s, e) => { if (step == 3) { DialogResult = DialogResult.OK; Close(); } else ShowStep(step + 1); };
            action.Click += async (s, e) => await DoAction();
            ShowStep(0);
        }

        void ShowStep(int i)
        {
            step = i;
            result.Text = "";
            back.Enabled = step > 0;
            next.Text = step == 3 ? "Готово" : "Далее";
            stepLabel.Text = step == 0 || step == 3 ? "" : "Шаг " + step + " из 2";
            action.Visible = true; action.Enabled = true;
            switch (step)
            {
                case 0:
                    title.Text = "Добро пожаловать в WinUp";
                    body.Text = "WinUp помогает быстро настроить компьютер:\n\n" +
                                "•  собирает установщики программ в одном месте и ставит их пачкой — без бесконечных «Далее»;\n" +
                                "•  хранит ссылки на официальные сайты, где скачать программы;\n" +
                                "•  хранит ваши логины и пароли в зашифрованной базе и сам входит на сайты и в программы.\n\n" +
                                "Два коротких шага — и всё готово. Мастер можно пропустить и открыть позже: Меню → Мастер первого запуска.";
                    action.Visible = false;
                    break;
                case 1:
                    title.Text = "Программы";
                    body.Text = "Скорее всего, установщики нужных программ уже лежат на этом компьютере — в Загрузках, на Рабочем столе, в Документах.\n\n" +
                                "WinUp их найдёт, уберёт повторы и старые версии и скопирует в свою папку apps. Оригиналы останутся на месте.\n\n" +
                                "Нужной программы нет? Скачайте её на вкладке «Скачать» и поищите снова (Меню → Найти установщики на ПК).";
                    action.Text = "Найти установщики на ПК...";
                    break;
                case 2:
                    title.Text = "Пароли (по желанию)";
                    body.Text = "WinUp может хранить логины и пароли и сам входить на сайты и в программы.\n\n" +
                                "База шифруется паролем базы — он же открывает вкладку «Пароли». " +
                                "Ещё будет код восстановления — запишите его: он выручит, если пароль забудется.\n\n" +
                                "Пароли сейчас не нужны — просто нажмите «Далее».";
                    action.Text = hasVault ? "База паролей уже есть" : "Создать базу паролей...";
                    action.Enabled = !hasVault;
                    break;
                case 3:
                    title.Text = "Готово!";
                    body.Text = "Где что находится:\n\n" +
                                "•  «Пароли» — учётные записи для сайтов и приложений;\n" +
                                "•  «2FA» — одноразовые коды; «Ключи доступа» — вход через своё расширение;\n" +
                                "•  «Файлы» — шифрованные файлы и папки;\n" +
                                "•  «Запуск» — портативные программы; «WinGet» — каталог программ;\n" +
                                "•  «Установка» — очередь установщиков; «Скачать» — ссылки на сайты.\n\n" +
                                "Новые установщики просто кладите в папку apps — WinUp сам предложит их добавить.";
                    action.Text = "Открыть инструкцию";
                    break;
            }
        }

        async Task DoAction()
        {
            action.Enabled = false;
            try
            {
                if (step == 1)
                {
                    int n = await findInstallers();
                    result.Text = n > 0 ? "Добавлено программ: " + n + ". Они на вкладке «Установка» (портативные — на «Запуске»)." : "Ничего не добавлено.";
                }
                else if (step == 2)
                {
                    if (createVault()) { hasVault = true; result.Text = "База паролей создана."; action.Text = "База паролей уже есть"; return; }
                    result.Text = "База не создана — можно вернуться к этому позже на вкладке «Пароли».";
                }
                else if (step == 3) openHelp();
            }
            finally { if (!(step == 2 && hasVault)) action.Enabled = true; }
        }
    }
}

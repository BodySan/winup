using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace WinUp
{
    // Добавление/изменение аккаунта 2FA вручную: ключ из текста под QR-кодом или ссылка otpauth://.
    class OtpDialog : Dlg, ILockableDialog
    {
        readonly OtpEntry o;
        readonly TextBox issuer = new TextBox(), account = new TextBox(), secret = new TextBox(), notes = new TextBox();
        readonly ComboBox algo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList }, digits = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList },
                          period = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        readonly Label preview = new Label { AutoSize = true, Font = new Font("Consolas", 14f), Margin = new Padding(3, 4, 3, 3) };
        readonly System.Windows.Forms.Timer tick = new System.Windows.Forms.Timer { Interval = 1000 };

        public OtpDialog(OtpEntry entry, bool isNew) : base(isNew ? "Новый аккаунт 2FA" : "Аккаунт 2FA")
        {
            o = entry;
            Note("Когда сайт включает 2FA, он показывает QR-код и рядом ключ («Не получается отсканировать? Введите код вручную»). " +
                 "Вставьте этот ключ сюда и отсканируйте QR телефоном — коды в WinUp и в телефоне будут одинаковыми.");
            Row("Сервис:", issuer);
            Row("Аккаунт (логин, почта):", account);
            Row("Ключ или ссылка otpauth://:", secret);
            algo.Items.AddRange(new object[] { "SHA1", "SHA256", "SHA512" });
            digits.Items.AddRange(new object[] { "6", "8" });
            period.Items.AddRange(new object[] { "30", "60" });
            var adv = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty };
            adv.Controls.Add(algo); adv.Controls.Add(new Label { Text = "цифр:", AutoSize = true, Margin = new Padding(6, 7, 0, 0) }); adv.Controls.Add(digits);
            adv.Controls.Add(new Label { Text = "период, с:", AutoSize = true, Margin = new Padding(6, 7, 0, 0) }); adv.Controls.Add(period);
            algo.Width = digits.Width = period.Width = 70;
            Row("Параметры:", adv);
            Note("Параметры почти всегда SHA1 / 6 / 30 — меняйте, только если сайт указал другие.", SystemColors.GrayText);
            Row("Код сейчас:", preview);
            Row("Заметка:", notes);
            Buttons();

            issuer.Text = o.Issuer; account.Text = o.Account; o.UseSecret(s => { var handle = secret.Handle; secret.Text = s; return 0; }); notes.Text = o.Notes;
            algo.SelectedItem = algo.Items.Contains(o.Algorithm) ? o.Algorithm : "SHA1";
            digits.SelectedItem = o.Digits == 8 ? "8" : "6";
            // Нестандартное число цифр (7 после импорта извне) не должно молча превращаться в 6 при редактировании.
            if (!digits.Items.Contains(o.Digits.ToString())) { digits.Items.Add(o.Digits.ToString()); digits.SelectedItem = o.Digits.ToString(); }
            period.SelectedItem = o.Period == 60 ? "60" : "30";
            if (!period.Items.Contains(o.Period.ToString())) { period.Items.Add(o.Period.ToString()); period.SelectedItem = o.Period.ToString(); }

            secret.TextChanged += (s, e) => FromLink();
            foreach (var c in new[] { algo, digits, period }) c.SelectedIndexChanged += (s, e) => UpdatePreview();
            UpdatePreview();
            // «Код сейчас» живёт и сам: без таймера через period секунд показывался устаревший код.
            tick.Tick += (s, e) => UpdatePreview();
            tick.Start();
            FormClosed += (s, e) => { tick.Stop(); tick.Dispose(); };
            Ok.Click += (s, e) => Commit();
        }

        // Вставили ссылку otpauth:// — разбираем в поля.
        void FromLink()
        {
            var t = secret.Text.Trim();
            if (t.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                var parsed = OtpImport.FromUri(t, new List<string>());
                if (parsed != null)
                {
                    if (issuer.Text.Trim().Length == 0) issuer.Text = parsed.Issuer;
                    if (account.Text.Trim().Length == 0) account.Text = parsed.Account;
                    algo.SelectedItem = parsed.Algorithm; digits.SelectedItem = parsed.Digits == 8 ? "8" : "6";
                    if (!digits.Items.Contains(parsed.Digits.ToString())) digits.Items.Add(parsed.Digits.ToString());
                    digits.SelectedItem = parsed.Digits.ToString();
                    if (!period.Items.Contains(parsed.Period.ToString())) period.Items.Add(parsed.Period.ToString());
                    period.SelectedItem = parsed.Period.ToString();
                    parsed.UseSecret(value => { secret.Text = value; return 0; });
                    return;
                }
            }
            UpdatePreview();
        }

        void UpdatePreview()
        {
            string s = null;
            try
            {
                s = Totp.Normalize(secret.Text);
                preview.Text = s.Length == 0 ? "—" : Totp.Code(s, (string)algo.SelectedItem, int.Parse((string)digits.SelectedItem), int.Parse((string)period.SelectedItem),
                                                              DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                preview.ForeColor = SystemColors.ControlText;
            }
            catch (FormatException ex) { preview.Text = ex.Message; preview.ForeColor = Color.Firebrick; }
            finally { Secure.Wipe(s); }
        }

        void Commit()
        {
            var s = Totp.Normalize(secret.Text);
            try
            {
            if (issuer.Text.Trim().Length == 0) { Fail("Укажите сервис (например, Google)."); return; }
            if (s.Length == 0) { Fail("Вставьте ключ или ссылку otpauth://."); return; }
            try { Totp.Code(s); } catch (FormatException ex) { Fail(ex.Message); return; }
            o.Issuer = issuer.Text.Trim(); o.Account = account.Text.Trim(); o.Secret = s; o.Notes = notes.Text;
            o.Algorithm = (string)algo.SelectedItem; o.Digits = int.Parse((string)digits.SelectedItem); o.Period = int.Parse((string)period.SelectedItem);
            }
            finally { Secure.Wipe(s); }
        }
    }

    // Импорт аккаунтов 2FA из другого приложения: вставить ссылку/текст или открыть файл экспорта.
    // ILockableDialog: поле ввода содержит секреты из экспорта — при блокировке базы окно закрывается.
    class OtpImportDialog : Form, ILockableDialog
    {
        readonly TextBox input = new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f) };
        readonly ListView lv = new ListView { View = View.Details, CheckBoxes = true, FullRowSelect = true, Dock = DockStyle.Fill };
        readonly Label warn = new Label { Dock = DockStyle.Bottom, Height = 44, ForeColor = Color.DarkOrange, AutoEllipsis = true, UseMnemonic = false }; // «&» в ссылках не съедается
        readonly Button add = new Button { Text = "Добавить отмеченные", AutoSize = true, Enabled = false };
        readonly HashSet<string> existing;
        public readonly List<OtpEntry> Selected = new List<OtpEntry>();

        // Импорт показывает секреты 2FA — окно вне записи экрана.
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Win.ApplyCaptureProtection(this);
        }

        public OtpImportDialog(IEnumerable<OtpEntry> already)
        {
            existing = new HashSet<string>(already.Select(x => x.UseSecret(BrowserPair.HashToken)));
            Text = "Импорт кодов 2FA из другого приложения";
            Font = new Font("Segoe UI", 9f);
            Size = new Size(900, 680);
            StartPosition = FormStartPosition.CenterParent;

            var help = new Label
            {
                Dock = DockStyle.Top, Height = 190, Padding = new Padding(6),
                Text =
                "Google Authenticator: меню → «Перенос аккаунтов» → «Экспорт» → выберите аккаунты → появится QR-код.\n" +
                "    Считайте QR офлайн на своём устройстве: нужна ссылка otpauth-migration://...\n" +
                "    Перенесите её на ПК через защищённый канал или собственный носитель и вставьте ниже. Несколько QR — вставьте все ссылки.\n" +
                "Aegis: Настройки → Импорт и экспорт → Экспорт → формат JSON, без шифрования → «Открыть файл».\n" +
                "2FAS: Настройки → Резервная копия → Экспорт в файл без пароля (.2fas) → «Открыть файл».\n" +
                "andOTP, FreeOTP+, Ente Auth, Bitwarden: экспорт в файл или текст (ссылки otpauth://) → «Открыть файл» или вставьте текст.\n" +
                "Если ваше приложение не экспортирует секреты, заново подключите 2FA для нужных аккаунтов на самих сайтах.\n\n" +
                "Файлы экспорта содержат секреты открытым текстом — удалите их с телефона и компьютера после импорта."
            };
            var top = new Panel { Dock = DockStyle.Top, Height = 130, Padding = new Padding(6) };
            var inBar = new FlowLayoutPanel { Dock = DockStyle.Right, Width = 170, FlowDirection = FlowDirection.TopDown };
            var open = new Button { Text = "Открыть файл...", AutoSize = true };
            var find = new Button { Text = "Найти коды", AutoSize = true, Font = new Font("Segoe UI", 9f, FontStyle.Bold) };
            inBar.Controls.Add(open); inBar.Controls.Add(find);
            top.Controls.Add(input); top.Controls.Add(inBar);
            lv.Columns.Add("Сервис", 220); lv.Columns.Add("Аккаунт", 260); lv.Columns.Add("Параметры", 150); lv.Columns.Add("", 160);
            var bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(4) };
            var close = new Button { Text = "Закрыть", AutoSize = true, DialogResult = DialogResult.Cancel };
            bottom.Controls.Add(add); bottom.Controls.Add(close);
            CancelButton = close;
            Controls.Add(lv); Controls.Add(warn); Controls.Add(top); Controls.Add(help); Controls.Add(bottom);

            open.Click += (s, e) =>
            {
                using (var d = new OpenFileDialog { Filter = "Экспорт аутентификатора (*.json;*.2fas;*.txt;*.csv)|*.json;*.2fas;*.txt;*.csv|Все файлы|*.*" })
                    if (d.ShowDialog(this) == DialogResult.OK)
                    {
                        try { input.Text = File.ReadAllText(d.FileName); Find(); }
                        catch (Exception ex) { warn.Text = ex.Message; }
                    }
            };
            find.Click += (s, e) => Find();
            lv.ItemChecked += (s, e) => add.Enabled = lv.CheckedItems.Count > 0;
            add.Click += (s, e) => { Selected.AddRange(lv.CheckedItems.Cast<ListViewItem>().Select(i => (OtpEntry)i.Tag)); DialogResult = DialogResult.OK; Close(); };
            FormClosed += (s, e) => input.Clear();
        }

        void Find()
        {
            var warnings = new List<string>();
            var found = OtpImport.Parse(input.Text, warnings);
            lv.BeginUpdate(); lv.Items.Clear();
            foreach (var o in found)
            {
                bool have = existing.Contains(o.UseSecret(BrowserPair.HashToken));
                lv.Items.Add(new ListViewItem(new[] { o.Issuer, o.Account, o.Algorithm + " / " + o.Digits + " / " + o.Period + " с", have ? "уже есть в WinUp" : "" })
                { Tag = o, Checked = !have, ForeColor = have ? SystemColors.GrayText : SystemColors.WindowText });
            }
            lv.EndUpdate();
            add.Enabled = lv.CheckedItems.Count > 0;
            warn.Text = (found.Count > 0 ? "Найдено аккаунтов: " + found.Count + ". " : "") + string.Join("  ", warnings);
        }
    }
}

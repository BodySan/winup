using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinUp
{
    // Найденный на ПК файл программы.
    public class FoundFile
    {
        public string Path;
        public string Name;          // как показать: название продукта или имя файла
        public string Version;
        public string Description;   // из свойств файла
        public string Kind;          // "install" | "portable"
        public string Args;
        public string Note;
        public long Size;
        public DateTime Date;
        public int Copies = 1;       // сколько похожих файлов (копий/версий) найдено
        public bool InWinUp;         // такой файл уже есть в apps\
    }

    // Поиск установщиков в выбранных папках: системные и служебные места пропускаются,
    // копии и разные версии одной программы схлопываются в одну строку (берётся самая свежая).
    static class InstallerSearch
    {
        [DllImport("shell32.dll")] static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid id, uint flags, IntPtr token, out IntPtr path);

        public static string Downloads()
        {
            IntPtr p;
            if (SHGetKnownFolderPath(new Guid("374DE290-123F-4565-9164-39C4925E467B"), 0, IntPtr.Zero, out p) == 0)
            {
                var s = Marshal.PtrToStringUni(p);
                Marshal.FreeCoTaskMem(p);
                return s;
            }
            return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        }

        static readonly string[] SkipNames = { "$Recycle.Bin", "System Volume Information", "node_modules", ".git", "WinSxS", "Windows", "AppData" };
        static readonly Regex InstallerName = new Regex(@"setup|install|инстал|установ", RegexOptions.IgnoreCase);

        static List<string> SkipRoots()
        {
            var list = new List<string>();
            foreach (var v in new[] { "%WINDIR%", "%ProgramFiles%", "%ProgramFiles(x86)%", "%ProgramData%", "%LocalAppData%", "%AppData%", "%TEMP%" })
            {
                var p = Environment.ExpandEnvironmentVariables(v);
                if (!p.Contains("%")) list.Add(p.TrimEnd('\\') + "\\");
            }
            list.Add(Paths.RootPrefix); // сам WinUp (корректно и для установки в корень диска: "E:\\" )
            return list;
        }

        public static List<FoundFile> Run(IEnumerable<string> roots, bool includePortable, HashSet<string> inWinUp, IProgress<string> progress, CancellationToken ct)
        {
            var skip = SkipRoots();
            var files = new List<FoundFile>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var stack = new Stack<string>(roots.Where(Directory.Exists));
            int dirs = 0;
            while (stack.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var dir = stack.Pop();
                if (!seen.Add(dir)) continue;
                if (++dirs % 50 == 0) progress.Report("Просмотрено папок: " + dirs + ", найдено: " + files.Count + " — " + dir);
                string[] sub, here;
                try { sub = Directory.GetDirectories(dir); here = Directory.GetFiles(dir); }
                catch { continue; } // нет доступа — пропускаем
                foreach (var d in sub)
                {
                    try
                    {
                        var info = new DirectoryInfo(d);
                        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue; // ссылки на другие папки — без петель
                        if (SkipNames.Contains(info.Name, StringComparer.OrdinalIgnoreCase)) continue;
                        var full = d.TrimEnd('\\') + "\\";
                        if (skip.Any(s => full.StartsWith(s, StringComparison.OrdinalIgnoreCase))) continue;
                        stack.Push(d);
                    }
                    catch { }
                }
                foreach (var f in here)
                {
                    var ext = System.IO.Path.GetExtension(f).ToLowerInvariant();
                    if (ext != ".exe" && ext != ".msi") continue;
                    ct.ThrowIfCancellationRequested();
                    var ff = Inspect(f, includePortable);
                    if (ff == null) continue;
                    ff.InWinUp = inWinUp.Contains(System.IO.Path.GetFileName(f).ToLowerInvariant() + "|" + ff.Size);
                    files.Add(ff);
                }
            }
            progress.Report("Сравниваю версии...");
            return Group(files);
        }

        static FoundFile Inspect(string f, bool includePortable)
        {
            FileInfo fi;
            try { fi = new FileInfo(f); } catch { return null; }
            if (fi.Length < 50 * 1024) return null; // мелкие служебные exe
            string args, note;
            bool installer = Detect.Guess(f, out args, out note);
            string verDesc = "";
            try { var vi = FileVersionInfo.GetVersionInfo(f); verDesc = (vi.FileDescription ?? "") + " " + (vi.InternalName ?? ""); } catch { }
            if (!installer && (InstallerName.IsMatch(fi.Name) || InstallerName.IsMatch(verDesc)))
            { installer = true; args = ""; note = "похоже на установщик, тип не распознан — установка вручную"; }
            if (!installer && !includePortable) return null;
            // «Веб-загрузчик» — по названию или совсем малому размеру: порог 3 МБ помечал полноценные
            // установщики (smartmontools 1,5 МБ, 7-Zip 1,6 МБ) как требующие интернет.
            if (installer && !f.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) &&
                (fi.Length < 1024 * 1024 || Regex.IsMatch(fi.Name, @"online|web|stub|bootstrap|downloader", RegexOptions.IgnoreCase)))
                note += "; похоже на веб-загрузчик (нужен интернет)";
            var ff = new FoundFile
            {
                Path = f, Size = fi.Length, Date = fi.LastWriteTime, Kind = installer ? "install" : "portable",
                Args = installer ? args : "", Note = installer ? note : "портативная программа (не установщик)",
                Name = System.IO.Path.GetFileNameWithoutExtension(f), Version = "", Description = ""
            };
            try
            {
                var v = FileVersionInfo.GetVersionInfo(f);
                var product = (v.ProductName ?? "").Trim();
                var desc = (v.FileDescription ?? "").Trim();
                if (product.Length > 1 && !Regex.IsMatch(product, @"^(setup|installer)$", RegexOptions.IgnoreCase)) ff.Name = product;
                ff.Version = (v.ProductVersion ?? v.FileVersion ?? "").Trim();
                var company = (v.CompanyName ?? "").Trim();
                var text = desc.Length > 1 && !string.Equals(desc, product, StringComparison.OrdinalIgnoreCase) ? desc : product;
                ff.Description = (text + (company.Length > 1 ? " (" + company + ")" : "")).Trim();
            }
            catch { }
            return ff;
        }

        // Ключ для поиска одинаковых программ: без версий, «(1)», слов setup/x64 и т. п.
        static string GroupKey(FoundFile f)
        {
            var s = (f.Name + " ").ToLowerInvariant();
            s = Regex.Replace(s, @"\(\d+\)", " ");
            s = Regex.Replace(s, @"v?\d+([._-]\d+)+", " ");
            s = Regex.Replace(s, @"\b(setup|installer|install|x64|x86|win64|win32|amd64|arm64|64-bit|32-bit|64bit|32bit|full|offline|online|latest|portable|ru|en)\b", " ");
            s = Regex.Replace(s, @"[^\p{L}\p{N}]+", "");
            return (s.Length == 0 ? System.IO.Path.GetFileName(f.Path).ToLowerInvariant() : s) + "|" + f.Kind;
        }

        static Version ParseVersion(string v)
        {
            var m = Regex.Match(v ?? "", @"\d+(\.\d+){0,3}");
            Version r;
            return m.Success && Version.TryParse(m.Value.Contains(".") ? m.Value : m.Value + ".0", out r) ? r : new Version(0, 0);
        }

        static List<FoundFile> Group(List<FoundFile> files)
        {
            var result = new List<FoundFile>();
            foreach (var g in files.GroupBy(GroupKey))
            {
                var best = g.OrderByDescending(f => ParseVersion(f.Version)).ThenByDescending(f => f.Date).First();
                best.Copies = g.Count();
                best.InWinUp = g.Any(f => f.InWinUp);
                result.Add(best);
            }
            return result.OrderBy(f => f.Kind == "install" ? 0 : 1).ThenBy(f => f.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        }
    }

    class InstallerSearchDialog : Form
    {
        readonly CheckedListBox places = new CheckedListBox { Dock = DockStyle.Fill, CheckOnClick = true, IntegralHeight = false };
        readonly CheckBox portable = new CheckBox { Text = "Показывать и портативные программы", AutoSize = true };
        readonly ListView lv = new ListView { View = View.Details, CheckBoxes = true, FullRowSelect = true, Dock = DockStyle.Fill };
        readonly Label status = new Label { Dock = DockStyle.Bottom, Height = 22, AutoEllipsis = true };
        readonly Button search = new Button { Text = "Искать", AutoSize = true }, take = new Button { Text = "Забрать отмеченные в WinUp", AutoSize = true, Enabled = false };
        readonly HashSet<string> inWinUp;
        CancellationTokenSource cts;
        public readonly List<FoundFile> Selected = new List<FoundFile>();

        public InstallerSearchDialog(HashSet<string> alreadyInWinUp)
        {
            inWinUp = alreadyInWinUp;
            Text = "WinUp — найти установщики на ПК";
            Font = new Font("Segoe UI", 9f);
            Size = new Size(980, 640);
            MinimumSize = new Size(760, 480);
            StartPosition = FormStartPosition.CenterParent;

            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            AddPlace(InstallerSearch.Downloads(), true);
            AddPlace(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), true);
            AddPlace(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), true);
            foreach (var d in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady && d.Name.ToUpperInvariant() != "C:\\"))
                AddPlace(d.Name, false);

            var intro = new Label
            {
                Dock = DockStyle.Top, Height = 54, Padding = new Padding(6),
                Text = "WinUp поищет установщики программ в отмеченных местах (системные папки пропускаются) и соберёт их в одном месте — папке apps. " +
                       "Копии и старые версии одной программы показываются одной строкой: берётся самая свежая. Оригиналы остаются на месте."
            };
            var addPlace = new Button { Text = "Добавить папку или диск...", AutoSize = true };
            addPlace.Click += (s, e) =>
            {
                using (var d = new FolderBrowserDialog { Description = "Где ещё искать установщики" })
                    if (d.ShowDialog(this) == DialogResult.OK) AddPlace(d.SelectedPath, true);
            };
            var left = new Panel { Dock = DockStyle.Left, Width = 320, Padding = new Padding(6) };
            var leftBar = new TableLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, ColumnCount = 1 };
            portable.MaximumSize = new Size(300, 0);
            search.Font = new Font(Font.FontFamily, 10f, FontStyle.Bold);
            search.Padding = new Padding(12, 3, 12, 3);
            leftBar.Controls.Add(addPlace); leftBar.Controls.Add(portable); leftBar.Controls.Add(search);
            left.Controls.Add(places); left.Controls.Add(new Label { Text = "Где искать:", Dock = DockStyle.Top, Height = 20 }); left.Controls.Add(leftBar);

            lv.Columns.Add("Программа", 210); lv.Columns.Add("Версия", 80); lv.Columns.Add("Что это", 150); lv.Columns.Add("Размер", 70);
            lv.Columns.Add("Дата", 80); lv.Columns.Add("Копий", 50); lv.Columns.Add("Где лежит", 300);
            var tip = new ToolTip();
            lv.ItemMouseHover += (s, e) => tip.SetToolTip(lv, ((FoundFile)e.Item.Tag).Description + "\n" + ((FoundFile)e.Item.Tag).Note);
            lv.ShowItemToolTips = true;

            var bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(4) };
            var close = new Button { Text = "Закрыть", AutoSize = true, DialogResult = DialogResult.Cancel };
            var all = new Button { Text = "Отметить все / снять", AutoSize = true };
            bottom.Controls.AddRange(new Control[] { take, all, close });
            CancelButton = close;

            Controls.Add(lv); Controls.Add(left); Controls.Add(intro); Controls.Add(status); Controls.Add(bottom);

            search.Click += async (s, e) => await DoSearch();
            all.Click += (s, e) =>
            {
                bool on = lv.Items.Cast<ListViewItem>().Any(i => !i.Checked);
                foreach (ListViewItem i in lv.Items) i.Checked = on;
            };
            lv.ItemChecked += (s, e) => take.Enabled = lv.CheckedItems.Count > 0;
            take.Click += (s, e) =>
            {
                Selected.AddRange(lv.CheckedItems.Cast<ListViewItem>().Select(i => (FoundFile)i.Tag));
                DialogResult = DialogResult.OK; Close();
            };
            FormClosing += (s, e) => { if (cts != null) cts.Cancel(); };
            status.Text = "Отметьте места и нажмите «Искать».";
        }

        void AddPlace(string path, bool on)
        {
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) return;
            if (places.Items.Cast<string>().Any(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase))) return;
            places.Items.Add(path, on);
        }

        async Task DoSearch()
        {
            if (cts != null) { cts.Cancel(); return; } // кнопка работает как «Остановить»
            var roots = places.CheckedItems.Cast<string>().ToList();
            if (roots.Count == 0) { status.Text = "Отметьте хотя бы одно место."; return; }
            cts = new CancellationTokenSource();
            search.Text = "Остановить"; take.Enabled = false; lv.Items.Clear();
            var progress = new Progress<string>(m => status.Text = m);
            bool withPortable = portable.Checked;
            List<FoundFile> found = null;
            try { found = await Task.Run(() => InstallerSearch.Run(roots, withPortable, inWinUp, progress, cts.Token)); }
            catch (OperationCanceledException) { status.Text = "Поиск остановлен."; }
            catch (Exception ex) { status.Text = "Ошибка: " + ex.Message; }
            finally { cts = null; search.Text = "Искать"; }
            if (found == null) return;

            lv.BeginUpdate();
            foreach (var f in found)
            {
                var what = f.Kind == "install" ? (f.Note.Contains("веб-загрузчик") ? "установщик (веб)" : "установщик") : "портативная";
                var it = new ListViewItem(new[] { f.Name, f.Version, f.InWinUp ? "уже в WinUp" : what, Mb(f.Size), f.Date.ToString("dd.MM.yyyy"),
                    f.Copies > 1 ? f.Copies.ToString() : "", f.Path })
                { Tag = f, Checked = !f.InWinUp && f.Kind == "install", ToolTipText = (f.Description + "\n" + f.Note).Trim() };
                if (f.InWinUp) it.ForeColor = SystemColors.GrayText;
                lv.Items.Add(it);
            }
            lv.EndUpdate();
            take.Enabled = lv.CheckedItems.Count > 0;
            int inst = found.Count(f => f.Kind == "install");
            status.Text = "Найдено программ: " + found.Count + " (установщиков: " + inst + ")." +
                          (found.Count == 0 ? " Нужной программы нет? Скачайте установщик на вкладке «Скачать» и поищите снова." : " Отметьте нужные и нажмите «Забрать».");
        }

        static string Mb(long b) { return b >= 1024 * 1024 ? (b / 1024.0 / 1024.0).ToString("0.#") + " МБ" : (b / 1024) + " КБ"; }
    }
}

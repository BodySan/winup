using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Reflection;
using System.Windows.Forms;

namespace WinUp
{
    // Значки WinUp: синий «W» (тот же, что у расширения браузера) и серый с замком — база заблокирована.
    static class AppIcons
    {
        static Icon open, locked;

        public static Icon Open { get { if (open == null) open = Make(false); return open; } }
        public static Icon Locked { get { if (locked == null) locked = Make(true); return locked; } }

        static Icon Make(bool isLocked)
        {
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("browser/icon32.png"))
                using (var src = new Bitmap(s))
                using (var bmp = new Bitmap(32, 32, PixelFormat.Format32bppArgb))
                {
                    using (var g = Graphics.FromImage(bmp))
                    {
                        g.SmoothingMode = SmoothingMode.AntiAlias;
                        if (isLocked)
                        {
                            // Серый вариант: база закрыта, пароли недоступны.
                            var gray = new ColorMatrix(new[]
                            {
                                new[] { .3f, .3f, .3f, 0, 0 }, new[] { .59f, .59f, .59f, 0, 0 }, new[] { .11f, .11f, .11f, 0, 0 },
                                new[] { 0f, 0, 0, 1, 0 }, new[] { 0f, 0, 0, 0, 1 }
                            });
                            using (var ia = new ImageAttributes())
                            {
                                ia.SetColorMatrix(gray);
                                g.DrawImage(src, new Rectangle(0, 0, 32, 32), 0, 0, src.Width, src.Height, GraphicsUnit.Pixel, ia);
                            }
                            // Замок в правом нижнем углу.
                            using (var body = new SolidBrush(Color.FromArgb(255, 200, 120, 0)))
                            using (var shackle = new Pen(Color.FromArgb(255, 200, 120, 0), 2.5f))
                            using (var edge = new Pen(Color.White, 1.5f))
                            {
                                g.DrawArc(edge, 18, 13, 10, 11, 180, 180);
                                g.DrawArc(shackle, 18, 13, 10, 11, 180, 180);
                                g.FillRectangle(Brushes.White, 15, 19, 16, 13);
                                g.FillRectangle(body, 16, 20, 14, 11);
                            }
                        }
                        else g.DrawImage(src, new Rectangle(0, 0, 32, 32));
                    }
                    return Icon.FromHandle(bmp.GetHicon());
                }
            }
            catch { return isLocked ? SystemIcons.Shield : SystemIcons.Application; }
        }
    }

    // Значок в области уведомлений: состояние базы видно всегда, заблокировать можно, не открывая окно.
    sealed class TrayIcon : IDisposable
    {
        readonly NotifyIcon icon = new NotifyIcon();
        readonly ToolStripMenuItem lockItem = new ToolStripMenuItem("Заблокировать базу");
        readonly ToolStripMenuItem unlockItem = new ToolStripMenuItem("Открыть базу паролей...");

        public TrayIcon(Action show, Action lockVault, Action unlock, Action exit)
        {
            var menu = new ContextMenuStrip();
            var openItem = new ToolStripMenuItem("Открыть WinUp") { Font = new Font(SystemFonts.MenuFont, FontStyle.Bold) };
            openItem.Click += (s, e) => show();
            lockItem.Click += (s, e) => lockVault();
            unlockItem.Click += (s, e) => unlock();
            var exitItem = new ToolStripMenuItem("Выход");
            exitItem.Click += (s, e) => exit();
            menu.Items.AddRange(new ToolStripItem[] { openItem, lockItem, unlockItem, new ToolStripSeparator(), exitItem });
            icon.ContextMenuStrip = menu;
            icon.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) show(); };
            icon.MouseDoubleClick += (s, e) => { if (e.Button == MouseButtons.Left) show(); };
            // Подсказка в момент появления значка Windows 11 запоминает как его имя (список значков в параметрах
            // панели задач) и дописывает к ней текущую — поэтому при регистрации она просто «WinUp».
            icon.Icon = AppIcons.Locked;
            icon.Text = "WinUp";
            icon.Visible = true;
            SetLocked(true);
        }

        public void SetLocked(bool isLocked)
        {
            icon.Icon = isLocked ? AppIcons.Locked : AppIcons.Open;
            icon.Text = isLocked ? "WinUp: база паролей закрыта" : "WinUp: база паролей открыта";
            lockItem.Visible = !isLocked;
            unlockItem.Visible = isLocked;
        }

        public void Dispose()
        {
            icon.Visible = false; // иначе значок остаётся в области уведомлений до наведения мыши
            if (icon.ContextMenuStrip != null) icon.ContextMenuStrip.Dispose();
            icon.Dispose();
        }
    }
}

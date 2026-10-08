using System;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Windows.Forms;

namespace WinUp
{
    // Keep the native controls, keyboard navigation and UI Automation tree.
    // Only presentation changes; contrast themes retain the Windows palette.
    static class Appearance
    {
        static readonly Color Canvas = Color.FromArgb(243, 246, 251);
        static readonly Color Ink = Color.FromArgb(29, 43, 66);
        static readonly Color Muted = Color.FromArgb(85, 101, 124);
        static readonly Color Accent = Color.FromArgb(34, 84, 177);
        static readonly Color Line = Color.FromArgb(202, 212, 227);
        sealed class Applied { }
        static readonly ConditionalWeakTable<Control, Applied> applied = new ConditionalWeakTable<Control, Applied>();

        public static void Apply(Control control)
        {
            Applied marker;
            if (SystemInformation.HighContrast || applied.TryGetValue(control, out marker)) return;
            applied.Add(control, new Applied());
            control.SuspendLayout();
            try
            {
                if (control.BackColor == SystemColors.Control) control.BackColor = Canvas;
                if (control.ForeColor == SystemColors.ControlText || control.ForeColor == SystemColors.WindowText) control.ForeColor = Ink;
                else if (control.ForeColor == SystemColors.GrayText) control.ForeColor = Muted;
                var button = control as Button;
                if (button != null)
                {
                    button.FlatStyle = FlatStyle.Flat;
                    button.FlatAppearance.BorderSize = 1;
                    button.Padding = new Padding(7, 2, 7, 2);
                    if (button.AutoSize) button.MinimumSize = new Size(0, 29);
                    StyleButton(button);
                    button.TextChanged += delegate { StyleButton(button); };
                }
                var box = control as TextBox;
                if (box != null)
                {
                    box.BorderStyle = BorderStyle.FixedSingle;
                    box.BackColor = box.ReadOnly ? Color.FromArgb(235, 240, 248) : Color.White;
                    box.ForeColor = Ink;
                }
                var combo = control as ComboBox;
                if (combo != null) { combo.BackColor = Color.White; combo.ForeColor = Ink; }
                var list = control as ListView;
                if (list != null)
                {
                    list.BackColor = Color.White; list.ForeColor = Ink;
                    list.BorderStyle = BorderStyle.FixedSingle;
                }
                var menu = control as MenuStrip;
                if (menu != null) { menu.BackColor = Color.White; menu.ForeColor = Ink; }
                var page = control as TabPage;
                if (page != null) { page.UseVisualStyleBackColor = false; page.BackColor = Canvas; }
                var tabs = control as TabControl;
                if (tabs != null)
                {
                    tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
                    tabs.Padding = new Point(10, 8);
                    tabs.ItemSize = new Size(0, 32);
                    tabs.DrawItem += DrawTab;
                }
                foreach (Control child in control.Controls) Apply(child);
                control.ControlAdded += (sender, args) => Apply(args.Control);
            }
            finally { control.ResumeLayout(true); }
        }

        static void StyleButton(Button button)
        {
            bool primary = button.Text == "Войти" || button.Text == "ОК" ||
                button.Text == "Открыть..." || button.Text == "Создать базу..." ||
                button.Text == "Установить отмеченные" || button.Text == "Скачать комплект";
            bool remove = button.Text == "Удалить";
            button.UseVisualStyleBackColor = false;
            button.BackColor = primary ? Accent : Color.White;
            button.ForeColor = primary ? Color.White : remove ? Color.FromArgb(162, 42, 51) : Ink;
            button.FlatAppearance.BorderColor = primary ? Accent : remove ? Color.FromArgb(219, 175, 179) : Line;
            button.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(26, 66, 144) : Color.FromArgb(229, 237, 251);
            button.FlatAppearance.MouseDownBackColor = primary ? Color.FromArgb(21, 53, 118) : Color.FromArgb(214, 227, 249);
        }

        static void DrawTab(object sender, DrawItemEventArgs args)
        {
            var tabs = (TabControl)sender;
            bool selected = tabs.SelectedIndex == args.Index;
            var rect = args.Bounds;
            Color background = SystemInformation.HighContrast ? SystemColors.Control : selected ? Color.White : Canvas;
            Color foreground = SystemInformation.HighContrast ? SystemColors.ControlText : selected ? Accent : Muted;
            using (var brush = new SolidBrush(background)) args.Graphics.FillRectangle(brush, rect);
            TextRenderer.DrawText(args.Graphics, tabs.TabPages[args.Index].Text, tabs.Font, rect, foreground,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
            if (selected)
            {
                using (var brush = new SolidBrush(SystemInformation.HighContrast ? SystemColors.Highlight : Accent))
                    args.Graphics.FillRectangle(brush, rect.Left + 3, rect.Bottom - 3, Math.Max(0, rect.Width - 6), 3);
                if (tabs.Focused) ControlPaint.DrawFocusRectangle(args.Graphics, Rectangle.Inflate(rect, -4, -5), foreground, background);
            }
        }

        public static void MainStatus(Label label)
        {
            if (SystemInformation.HighContrast) return;
            label.BackColor = Color.FromArgb(30, 46, 72);
            label.ForeColor = Color.White;
            label.Height = 28;
            label.Padding = new Padding(10, 0, 6, 0);
        }
    }
}

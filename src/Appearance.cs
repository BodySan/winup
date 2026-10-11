using System;
using System.Drawing;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace WinUp
{
    // Keep the native controls, keyboard navigation and UI Automation tree.
    // Only presentation changes; contrast themes retain the Windows palette.
    static class Appearance
    {
        static bool dark=ReadDark();
        static bool ReadDark(){try{return !File.Exists(Path.Combine(Paths.Data,"desktop-theme.txt"))||File.ReadAllText(Path.Combine(Paths.Data,"desktop-theme.txt"))!="light";}catch{return true;}}
        static Color Canvas {get{return dark?Color.FromArgb(19,24,35):Color.FromArgb(243,246,251);}}
        static Color Surface {get{return dark?Color.FromArgb(28,35,49):Color.White;}}
        static Color Ink {get{return dark?Color.FromArgb(231,236,246):Color.FromArgb(29,43,66);}}
        static Color Muted {get{return dark?Color.FromArgb(157,173,199):Color.FromArgb(85,101,124);}}
        static Color Accent {get{return dark?Color.FromArgb(65,111,210):Color.FromArgb(34,84,177);}}
        static Color Line {get{return dark?Color.FromArgb(57,70,93):Color.FromArgb(202,212,227);}}
        sealed class Applied { internal Color OriginalFore,LastFore;internal NativeWindow Chrome; }
        static ConditionalWeakTable<Control, Applied> applied = new ConditionalWeakTable<Control, Applied>();
        public static void SetTheme(bool isDark){dark=isDark;foreach(Form form in Application.OpenForms){Apply(form);form.Invalidate(true);}}
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr window,int attribute,ref int value,int size);
        static void TitleBar(Form form){try{int value=dark?1:0;if(DwmSetWindowAttribute(form.Handle,20,ref value,4)!=0)DwmSetWindowAttribute(form.Handle,19,ref value,4);}catch{}}
        internal static double Contrast(Color a,Color b){return (Math.Max(Luminance(a),Luminance(b))+.05)/(Math.Min(Luminance(a),Luminance(b))+.05);}
        // Docked help/status labels have to grow when text wraps at a smaller width.
        internal static void WrapLabel(Label label,int minimumHeight=0){
            bool fitting=false;
            Action fit=()=>{if(fitting||label.IsDisposed)return;fitting=true;try{
                int width=Math.Max(32,label.ClientSize.Width-label.Padding.Horizontal);
                int height=TextRenderer.MeasureText(label.Text,label.Font,new Size(width,int.MaxValue),TextFormatFlags.WordBreak|TextFormatFlags.NoPrefix).Height+label.Padding.Vertical;
                label.Height=Math.Max(minimumHeight,height);
            }finally{fitting=false;}};
            label.SizeChanged+=(s,e)=>fit();label.TextChanged+=(s,e)=>fit();label.FontChanged+=(s,e)=>fit();fit();
        }
        static double Luminance(Color c){return .2126*Channel(c.R)+.7152*Channel(c.G)+.0722*Channel(c.B);}
        static double Channel(byte b){double n=b/255.0;return n<=.04045?n/12.92:Math.Pow((n+.055)/1.055,2.4);}
        internal static Color Semantic(Color color){
            if(color==SystemColors.ControlText||color==SystemColors.WindowText||color==Color.Black||color==Color.White)return Ink;
            if(color==SystemColors.GrayText)return Muted;
            for(int n=0;n<20&&Contrast(color,Canvas)<4.5;n++){int to=dark?255:0;color=Color.FromArgb((color.R*4+to)/5,(color.G*4+to)/5,(color.B*4+to)/5);}
            return color;
        }

        public static void Apply(Control control)
        {
            Applied marker;
            if (SystemInformation.HighContrast || control.GetType().FullName.StartsWith("Microsoft.Web.WebView2",StringComparison.Ordinal)) return;
            bool first=!applied.TryGetValue(control,out marker);
            if(first){marker=new Applied{OriginalFore=control.ForeColor,LastFore=control.ForeColor};applied.Add(control,marker);}
            else if(control.ForeColor!=marker.LastFore)marker.OriginalFore=control.ForeColor;
            control.SuspendLayout();
            try
            {
                control.BackColor=Canvas;
                control.ForeColor=Semantic(marker.OriginalFore);
                var form=control as Form;
                if(form!=null){if(form.IsHandleCreated)TitleBar(form);if(first)form.HandleCreated+=(s,e)=>TitleBar(form);}
                var button = control as Button;
                if (button != null)
                {
                    button.FlatStyle = FlatStyle.Flat;
                    button.FlatAppearance.BorderSize = 1;
                    button.Padding = new Padding(7, 2, 7, 2);
                    if (button.AutoSize) button.MinimumSize = new Size(0, 29);
                    StyleButton(button);
                    if(first){button.TextChanged += delegate { StyleButton(button); };button.EnabledChanged+=(s,e)=>button.Invalidate();button.Paint+=(s,e)=>{if(button.Enabled)return;using(var brush=new SolidBrush(Surface))e.Graphics.FillRectangle(brush,button.ClientRectangle);using(var pen=new Pen(Line))e.Graphics.DrawRectangle(pen,0,0,button.Width-1,button.Height-1);TextRenderer.DrawText(e.Graphics,button.Text,button.Font,Rectangle.Inflate(button.ClientRectangle,-5,-3),Muted,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.WordBreak);};}
                }
                var box = control as TextBoxBase;
                if (box != null)
                {
                    box.BorderStyle = BorderStyle.FixedSingle;
                    box.BackColor = box.ReadOnly ? Canvas : Surface;
                    box.ForeColor = Ink;
                }
                var combo = control as ComboBox;
                if (combo != null) { combo.BackColor = Surface; combo.ForeColor = Ink;if(first&&combo.DrawMode==DrawMode.Normal&&combo.DropDownStyle==ComboBoxStyle.DropDownList){combo.DrawMode=DrawMode.OwnerDrawFixed;combo.DrawItem+=DrawCombo;} }
                var updown=control as UpDownBase;
                if(updown!=null){updown.BackColor=Surface;updown.ForeColor=Ink;updown.BorderStyle=BorderStyle.FixedSingle;}
                var listBox=control as ListBox;
                if(listBox!=null){listBox.BackColor=Surface;listBox.ForeColor=Ink;listBox.BorderStyle=BorderStyle.FixedSingle;}
                var tree=control as TreeView;
                if(tree!=null){tree.BackColor=Surface;tree.ForeColor=Ink;tree.BorderStyle=BorderStyle.FixedSingle;tree.LineColor=Line;}
                var list = control as ListView;
                if (list != null)
                {
                    list.BackColor = Surface; list.ForeColor = Ink;
                    list.BorderStyle = BorderStyle.FixedSingle;
                    foreach(ListViewItem item in list.Items)if(item.ForeColor!=Color.Empty)item.ForeColor=Semantic(item.ForeColor);
                    if(first&&list.View==View.Details&&!list.OwnerDraw){list.OwnerDraw=true;list.DrawColumnHeader+=DrawHeader;list.DrawItem+=(s,e)=>e.DrawDefault=true;list.DrawSubItem+=(s,e)=>e.DrawDefault=true;if(list.Columns.Count>0){int minimum=list.Columns[list.Columns.Count-1].Width;list.Resize+=(s,e)=>{if(list.IsDisposed||list.Disposing||list.Columns.Count==0)return;int width=0;for(int i=0;i<list.Columns.Count-1;i++)width+=list.Columns[i].Width;list.Columns[list.Columns.Count-1].Width=Math.Max(minimum,list.ClientSize.Width-width-2);};}}
                }
                var grid=control as DataGridView;
                if(grid!=null){grid.BackgroundColor=Surface;grid.GridColor=Line;grid.EnableHeadersVisualStyles=false;grid.BorderStyle=BorderStyle.FixedSingle;StyleCells(grid.DefaultCellStyle,Surface);StyleCells(grid.RowsDefaultCellStyle,Surface);StyleCells(grid.AlternatingRowsDefaultCellStyle,Canvas);StyleCells(grid.ColumnHeadersDefaultCellStyle,Canvas);StyleCells(grid.RowHeadersDefaultCellStyle,Canvas);if(first)grid.EditingControlShowing+=(s,e)=>Apply(e.Control);}
                var menu = control as ToolStrip;
                if (menu != null) { StyleMenu(menu); }
                if(control.ContextMenuStrip!=null)StyleMenu(control.ContextMenuStrip);
                var page = control as TabPage;
                if (page != null) { page.UseVisualStyleBackColor = false; page.BackColor = Canvas; }
                var tabs = control as TabControl;
                if (tabs != null)
                {
                    tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
                    tabs.Padding = new Point(10, 8);
                    tabs.ItemSize = new Size(0, 32);
                    if(first){tabs.DrawItem += DrawTab;marker.Chrome=new TabChrome(tabs);}
                }
                foreach (Control child in control.Controls) Apply(child);
                marker.LastFore=control.ForeColor;
                if(first)control.ControlAdded += (sender, args) => Apply(args.Control);
            }
            finally { control.ResumeLayout(true); }
        }

        static void StyleCells(DataGridViewCellStyle style,Color background){style.BackColor=background;style.ForeColor=Ink;style.SelectionBackColor=Accent;style.SelectionForeColor=Color.White;}
        static void DrawHeader(object sender,DrawListViewColumnHeaderEventArgs e){using(var brush=new SolidBrush(Canvas))e.Graphics.FillRectangle(brush,e.Bounds);TextRenderer.DrawText(e.Graphics,e.Header.Text,((ListView)sender).Font,Rectangle.Inflate(e.Bounds,-6,0),Ink,TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix);using(var pen=new Pen(Line))e.Graphics.DrawLine(pen,e.Bounds.Right-1,e.Bounds.Top,e.Bounds.Right-1,e.Bounds.Bottom);}
        static void DrawCombo(object sender,DrawItemEventArgs e){var combo=(ComboBox)sender;bool selected=(e.State&DrawItemState.Selected)!=0;using(var brush=new SolidBrush(selected?Accent:Surface))e.Graphics.FillRectangle(brush,e.Bounds);if(e.Index>=0)TextRenderer.DrawText(e.Graphics,combo.GetItemText(combo.Items[e.Index]),combo.Font,Rectangle.Inflate(e.Bounds,-3,0),selected?Color.White:Ink,TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix);e.DrawFocusRectangle();}
        static void StyleMenu(ToolStrip menu){menu.BackColor=Surface;menu.ForeColor=Ink;menu.Renderer=new ToolStripProfessionalRenderer(new Palette());foreach(ToolStripItem item in menu.Items){item.BackColor=Surface;item.ForeColor=Ink;var parent=item as ToolStripDropDownItem;if(parent!=null)StyleMenu(parent.DropDown);}}
        sealed class Palette:ProfessionalColorTable{
            public override Color ToolStripDropDownBackground{get{return Surface;}}public override Color ImageMarginGradientBegin{get{return Surface;}}public override Color ImageMarginGradientMiddle{get{return Surface;}}public override Color ImageMarginGradientEnd{get{return Surface;}}public override Color MenuItemSelected{get{return Canvas;}}public override Color MenuItemBorder{get{return Line;}}public override Color MenuBorder{get{return Line;}}public override Color MenuStripGradientBegin{get{return Surface;}}public override Color MenuStripGradientEnd{get{return Surface;}}public override Color MenuItemPressedGradientBegin{get{return Canvas;}}public override Color MenuItemPressedGradientMiddle{get{return Canvas;}}public override Color MenuItemPressedGradientEnd{get{return Canvas;}}public override Color SeparatorDark{get{return Line;}}public override Color SeparatorLight{get{return Line;}}
        }
        sealed class TabChrome:NativeWindow {
            readonly TabControl tabs;
            internal TabChrome(TabControl tabs){this.tabs=tabs;if(tabs.IsHandleCreated)AssignHandle(tabs.Handle);tabs.HandleCreated+=(s,e)=>AssignHandle(tabs.Handle);tabs.HandleDestroyed+=(s,e)=>ReleaseHandle();}
            protected override void WndProc(ref Message message){base.WndProc(ref message);if(SystemInformation.HighContrast||tabs.IsDisposed||tabs.Disposing)return;if(message.Msg!=0x000f&&message.Msg!=0x0317&&message.Msg!=0x0318)return;
                try{using(var graphics=message.Msg==0x000f?Graphics.FromHwnd(tabs.Handle):Graphics.FromHdc(message.WParam))using(var brush=new SolidBrush(Canvas)){
                    var display=tabs.DisplayRectangle;int right=0;for(int i=0;i<tabs.TabCount;i++)right=Math.Max(right,tabs.GetTabRect(i).Right);
                    graphics.FillRectangle(brush,right+1,0,Math.Max(0,tabs.ClientSize.Width-right-1),Math.Max(0,display.Top-2));
                    graphics.FillRectangle(brush,0,display.Top-2,tabs.ClientSize.Width,2);graphics.FillRectangle(brush,0,display.Top,display.Left,tabs.ClientSize.Height-display.Top);
                    graphics.FillRectangle(brush,display.Right,display.Top,Math.Max(0,tabs.ClientSize.Width-display.Right),tabs.ClientSize.Height-display.Top);graphics.FillRectangle(brush,0,display.Bottom,tabs.ClientSize.Width,Math.Max(0,tabs.ClientSize.Height-display.Bottom));
                }}catch{}
            }
        }

        static void StyleButton(Button button)
        {
            bool primary = button.Text == "Войти" || button.Text == "ОК" ||
                button.Text == "Открыть..." || button.Text == "Создать базу..." ||
                button.Text == "Установить отмеченные" || button.Text == "Скачать комплект";
            bool remove = button.Text == "Удалить";
            button.UseVisualStyleBackColor = false;
            button.BackColor = primary ? Accent : Surface;
            button.ForeColor = primary ? Color.White : remove ? (dark?Color.FromArgb(245,142,151):Color.FromArgb(162,42,51)) : Ink;
            button.FlatAppearance.BorderColor = primary ? Accent : remove ? Color.FromArgb(219, 175, 179) : Line;
            button.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(26,66,144) : dark?Color.FromArgb(38,49,69):Color.FromArgb(229,237,251);
            button.FlatAppearance.MouseDownBackColor = primary ? Color.FromArgb(21,53,118) : dark?Color.FromArgb(45,59,82):Color.FromArgb(214,227,249);
        }

        static void DrawTab(object sender, DrawItemEventArgs args)
        {
            var tabs = (TabControl)sender;
            if(args.Index<0||args.Index>=tabs.TabPages.Count)return;
            bool selected = tabs.SelectedIndex == args.Index;
            var rect = args.Bounds;
            Color background = SystemInformation.HighContrast ? SystemColors.Control : selected ? Surface : Canvas;
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

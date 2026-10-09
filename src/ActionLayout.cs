using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace WinUp {
    // Each semantic group keeps its own row. Small windows scroll the actions,
    // rather than letting a growing toolbar cover the records underneath it.
    sealed class ActionGroup {
        internal readonly string Caption;
        internal readonly Control[] Items;
        internal ActionGroup(string caption,params Control[] items){Caption=caption;Items=items;}
    }
    sealed class SectionActions:Panel {
        readonly TableLayoutPanel rows=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,ColumnCount=1,Padding=new Padding(4,2,4,2),Margin=Padding.Empty};
        bool arranging;
        internal SectionActions(params ActionGroup[] groups){
            Dock=DockStyle.Top;AutoScroll=true;Margin=Padding.Empty;Controls.Add(rows);
            foreach(var group in groups){
                var row=new Panel{Dock=DockStyle.Fill,Margin=new Padding(0,0,0,3),Padding=new Padding(0,0,0,2)};
                var label=new Label{Text=group.Caption,Dock=DockStyle.Left,Width=92,TextAlign=ContentAlignment.MiddleLeft,Padding=new Padding(4),Font=new Font(SystemFonts.MessageBoxFont,FontStyle.Bold)};
                var flow=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=true,Margin=Padding.Empty,Padding=Padding.Empty};
                foreach(var item in group.Items){item.Margin=new Padding(3);item.TabIndex=flow.Controls.Count;flow.Controls.Add(item);item.Enter+=(s,e)=>ScrollControlIntoView((Control)s);}
                row.Controls.Add(flow);row.Controls.Add(label);rows.RowStyles.Add(new RowStyle(SizeType.Absolute,42));rows.Controls.Add(row,0,rows.RowCount++);
            }
            rows.SizeChanged+=(s,e)=>Fit();SizeChanged+=(s,e)=>Fit();VisibleChanged+=(s,e)=>Fit();
        }
        protected override void OnParentChanged(EventArgs e){base.OnParentChanged(e);if(Parent!=null){Parent.SizeChanged+=(s,a)=>Fit();Fit();}}
        void Fit(){
            if(arranging||Parent==null||IsDisposed)return;arranging=true;
            try{
                int occupied=Parent.Controls.Cast<Control>().Where(c=>c!=this&&(c.Dock==DockStyle.Top||c.Dock==DockStyle.Bottom)).Sum(c=>c.Height);
                int available=Math.Max(58,Parent.ClientSize.Height-occupied-140);
                int desired=rows.Padding.Vertical;
                for(int i=0;i<rows.Controls.Count;i++){
                    var row=(Panel)rows.Controls[i];var flow=row.Controls.OfType<FlowLayoutPanel>().Single();var label=row.Controls.OfType<Label>().Single();
                    int width=Math.Max(100,ClientSize.Width-rows.Padding.Horizontal-92-(VerticalScroll.Visible?SystemInformation.VerticalScrollBarWidth:0));
                    int height=Math.Max(TextRenderer.MeasureText(label.Text,label.Font,new Size(84,0),TextFormatFlags.WordBreak).Height+label.Padding.Vertical,flow.GetPreferredSize(new Size(width,0)).Height)+row.Padding.Vertical+row.Margin.Vertical;
                    rows.RowStyles[i].Height=height;desired+=height;
                }
                Height=Math.Min(desired,available);
            }finally{arranging=false;}
        }
    }
    partial class MainForm {
        static Control[] Actions(FlowLayoutPanel bar,params string[] names){return names.Select(n=>bar.Controls.Cast<Control>().First(c=>c.Text==n)).ToArray();}
        static void ArrangeActions(Control host,FlowLayoutPanel[] previous,params ActionGroup[] groups){
            var actions=new SectionActions(groups);actions.Name="SectionActions";
            foreach(var bar in previous){host.Controls.Remove(bar);bar.Dispose();}
            host.Controls.Add(actions);
        }
    }
}

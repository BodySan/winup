using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace WinUp
{
    sealed class LocalApplicationDialog : Dlg, ILockableDialog
    {
        readonly TextBox search=new TextBox();
        readonly ListView list=new ListView {View=View.Details,FullRowSelect=true,MultiSelect=false,HideSelection=false,Dock=DockStyle.Fill};
        readonly Label info=new Label {AutoSize=true};
        List<LocalApplication> apps=new List<LocalApplication>();
        public LocalApplication Selected {get;private set;}
        public LocalApplicationDialog(string service) : base("Выбрать установленное приложение") {
            AutoSize=false;ClientSize=new Size(710,480);
            Grid.Dock=DockStyle.Top;Grid.RowCount=2;
            Grid.ColumnStyles.Clear();Grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,80));Grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            Grid.Controls.Add(new Label {Text="Поиск:",AutoSize=true,Anchor=AnchorStyles.Left,Margin=new Padding(3,7,8,3)},0,0);
            search.Dock=DockStyle.Fill;Grid.Controls.Add(search,1,0);
            info.MaximumSize=new Size(680,0);info.Margin=new Padding(3,4,3,4);
            Grid.Controls.Add(info,0,1);Grid.SetColumnSpan(info,2);
            list.Columns.Add("Приложение",280);list.Columns.Add("Источник",320);
            var refresh=new Button {Text="Обновить список",AutoSize=true};
            var bottom=Buttons(refresh);Grid.Controls.Remove(bottom);bottom.Dock=DockStyle.Bottom;
            Controls.Add(list);Controls.Add(bottom);Grid.BringToFront();bottom.BringToFront();list.BringToFront();
            Ok.Text="Выбрать";Ok.Enabled=false;
            search.Text=AppStore.TemplateName(service);search.TextChanged+=(s,e)=>Filter();
            list.SelectedIndexChanged+=(s,e)=>Ok.Enabled=list.SelectedItems.Count==1;
            list.DoubleClick+=(s,e)=>{if(Ok.Enabled)Ok.PerformClick();};
            Ok.Click+=(s,e)=>{if(list.SelectedItems.Count==0){DialogResult=DialogResult.None;return;}Selected=(LocalApplication)list.SelectedItems[0].Tag;};
            EventHandler load=async (s,e)=>{
                refresh.Enabled=false;info.Text="Читаю список приложений Windows и ярлыки меню «Пуск»…";
                var result=await LocalApplications.Available(true);
                if(IsDisposed || Disposing)return;apps=result;Filter();refresh.Enabled=true;
            };
            refresh.Click+=load;Shown+=load;
        }
        void Filter() {
            var query=LocalApplications.Normalize(search.Text);list.BeginUpdate();list.Items.Clear();
            foreach(var app in apps.Where(a=>LocalApplications.Normalize(a.Name).Contains(query))) {
                var row=new ListViewItem(new[] {app.Name,app.Source}) {Tag=app,ToolTipText=app.Target};list.Items.Add(row);
            }
            list.EndUpdate();Ok.Enabled=false;
            info.Text=apps.Count==0 ? "Список Windows пока не получен. Нажмите «Обновить список» или выберите файл через «Обзор…» в записи." : list.Items.Count+" из "+apps.Count+". Не нашли? Очистите поиск. Для переносной программы используйте «Обзор…» в записи.";
        }
    }
}

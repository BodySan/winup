using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinUp {
    internal sealed class ComponentUpdatesDialog : Form {
        readonly ListView list=new ListView { Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true };
        readonly Label state=new Label { AutoSize=true,MaximumSize=new Size(940,0),Padding=new Padding(8) };
        readonly FlowLayoutPanel buttons=new FlowLayoutPanel { Dock=DockStyle.Bottom,AutoSize=true,WrapContents=true };
        readonly Action<string> log;
        readonly Action core,lockVault;
        List<ComponentVersionInfo> rows;
        ComponentRelease release;
        string checkedSource;
        bool busy;
        CancellationTokenSource cancellation;
        Button download;
        public ComponentUpdatesDialog(Action<string> logger,Action coreUpdate,Action lockAction) {
            log=logger; core=coreUpdate; lockVault=lockAction;
            Text="WinUp — обновления компонентов"; StartPosition=FormStartPosition.CenterParent;
            Size=new Size(1000,570); MinimumSize=new Size(780,450); Font=new Font("Segoe UI",9);
            list.Columns.Add("Компонент",245); list.Columns.Add("Используется",155); list.Columns.Add("На официальном источнике",160); list.Columns.Add("Состояние",410);
            Controls.Add(list); Controls.Add(state); state.Dock=DockStyle.Top; Controls.Add(buttons);
            Add("Проверить",Check);
            Add("Источник пакетов…",Configure);
            download=Add("Скачать комплект",Download);
            Add("Установить из файла…",Import);
            Add("Обновить KeePass",delegate { core(); RefreshRows(); });
            Add("Обновить WinFsp",UpdateDriver);
            Add("Откат…",Rollback);
            Add("Перезапустить",delegate { CoreUpdate.RestartPendingFlag=true; Close(); });
            Add("Закрыть",Close);
            FormClosing+=(s,e)=> { if(busy) { e.Cancel=true; if(cancellation!=null) cancellation.Cancel(); state.Text="Завершаю операцию…"; } };
            RefreshRows();
        }
        Button Add(string text,Action action) { var button=new Button { Text=text,AutoSize=true,Margin=new Padding(4) }; button.Click+=(s,e)=>action(); buttons.Controls.Add(button); return button; }
        void RefreshRows() {
            rows=ComponentInventory.Rows(); list.Items.Clear(); foreach(var row in rows) list.Items.Add(new ListViewItem(new[] {row.Name,row.Installed,row.Latest ?? "—",row.Status}) {Tag=row});
            ComponentState selected;
            try { selected=ComponentResources.Store.State(); }
            catch(Exception ex) { state.Text="Используется проверенный комплект. Состояние обновлений повреждено: "+ex.Message; download.Enabled=false; return; }
            string pending=selected.active!=ComponentResources.CurrentId ? " Выбран другой комплект: применится после перезапуска." : "";
            state.Text=(ComponentResources.CurrentId==null ? "Используется встроенный комплект." : "Используется подписанный комплект №"+ComponentResources.Current.sequence+".")+pending+
                "\n"+SourceDescription()+
                (ComponentResources.Note==null ? "" : "\n"+ComponentResources.Note);
            download.Enabled=release!=null && release.sequence>selected.highest;
        }
        string SourceDescription() {
            try { string source=ComponentFeed.Source; return source.Length==0 ? "Источник пакетов WinUp не настроен. Проверка официальных версий работает отдельно; комплект можно установить из файла." : "Источник пакетов: "+source; }
            catch(Exception ex) { return "Источник пакетов недоступен: "+ex.Message; }
        }
        void EnableDownload() { try { download.Enabled=release!=null && release.sequence>ComponentResources.Store.State().highest; } catch { download.Enabled=false; } }
        void Change(ComponentVersionInfo row) {
            if(IsDisposed) return;
            var item=list.Items.Cast<ListViewItem>().First(x=>ReferenceEquals(x.Tag,row)); item.SubItems[2].Text=row.Latest ?? "—"; item.SubItems[3].Text=row.Status;
        }
        async void Run(Action<CancellationToken> action,Action done=null) {
            if(busy) return; busy=true; cancellation=new CancellationTokenSource(); foreach(Control control in buttons.Controls) control.Enabled=false;
            try { await Task.Run(delegate { action(cancellation.Token); }); if(done!=null) done(); }
            catch(OperationCanceledException) { state.Text="Операция отменена. Текущий комплект продолжает работать."; }
            catch(Exception ex) { MessageBox.Show(this,ex.Message,Text,MessageBoxButtons.OK,MessageBoxIcon.Warning); }
            finally { cancellation.Dispose(); cancellation=null; busy=false; foreach(Control control in buttons.Controls) control.Enabled=true; EnableDownload(); }
        }
        void Check() {
            try { checkedSource=ComponentFeed.Source; } catch(Exception ex) { MessageBox.Show(this,ex.Message,Text); return; } release=null;
            Run(delegate(CancellationToken token) {
                ComponentInventory.Check(rows,delegate(ComponentVersionInfo row) { token.ThrowIfCancellationRequested(); Invoke((MethodInvoker)delegate { Change(row); }); });
                if(checkedSource.Length>0) release=ComponentFeed.Check(checkedSource,token);
            },delegate {
                state.Text=release==null ? "Проверка официальных версий завершена. Источник наших пакетов не настроен." :
                    release.sequence>ComponentResources.Store.State().highest ? "Доступен подписанный комплект №"+release.sequence+". Нажмите «Скачать комплект»." : "Новый комплект WinUp не обнаружен.";
            });
        }
        void Configure() {
            string source; try { source=ComponentFeed.Source; } catch(Exception ex) { MessageBox.Show(this,ex.Message,Text); return; }
            using(var dialog=new ComponentSourceDialog(source)) {
                if(dialog.ShowDialog(this)!=DialogResult.OK) return;
                try { ComponentFeed.Source=dialog.Value; release=null; RefreshRows(); } catch(Exception ex) { MessageBox.Show(this,ex.Message,Text); }
            }
        }
        void Import() {
            using(var dialog=new OpenFileDialog { Filter="Подписанный комплект WinUp (*.wup)|*.wup",CheckFileExists=true }) {
                if(dialog.ShowDialog(this)!=DialogResult.OK) return;
                string path=dialog.FileName;
                Run(delegate { using(var inspected=ComponentResources.Store.Inspect(path)) {} },delegate {
                    if(MessageBox.Show(this,"Пакет проверен. Подготовить его для применения после перезапуска?",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
                    // Queue outside the completion callback, while Run is still marked busy.
                    BeginInvoke((MethodInvoker)delegate { Run(delegate { ComponentResources.Store.Install(path); },Installed); });
                });
            }
        }
        void Download() {
            if(release==null || MessageBox.Show(this,"Скачать проверенный комплект №"+release.sequence+" и подготовить его к перезапуску?",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
            var selected=release; string source=checkedSource;
            Run(token=>ComponentFeed.Install(selected,source,token),Installed);
        }
        void Installed() { if(log!=null) log("Комплект компонентов проверен и подготовлен. Требуется перезапуск WinUp."); release=null; RefreshRows(); }
        void Rollback() {
            if(MessageBox.Show(this,"Вернуться к предыдущему проверенному комплекту? Изменение применится после перезапуска; данные хранилищ не меняются.",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
            Run(delegate { ComponentResources.Store.Rollback(); },Installed);
        }
        void UpdateDriver() {
            if(MessageBox.Show(this,"Проверить и установить официальный WinFsp? Файловые хранилища будут закрыты. Windows запросит права администратора; может потребоваться перезагрузка Windows.",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
            lockVault(); string result=null;
            Run(token=>result=WinFspDriver.UpdateOfficial(token),delegate { RefreshRows(); MessageBox.Show(this,result,Text); });
        }
    }
    internal sealed class ComponentSourceDialog : Dlg {
        readonly TextBox box=new TextBox();
        public string Value { get { return box.Text; } }
        public ComponentSourceDialog(string source) : base("Источник пакетов WinUp") {
            box.Text=source;
            Note("HTTPS-адрес папки с update.json, update.sig и комплектом. Для GitHub: https://github.com/владелец/репозиторий/releases/latest/download/. Пустое поле отключает загрузку наших пакетов.");
            Row("Адрес:",box); Buttons();
        }
    }
}

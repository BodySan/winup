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
        readonly ListView list=new ListView { Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,ShowItemToolTips=true };
        readonly Label state=new Label { AutoSize=true,MaximumSize=new Size(940,0),Padding=new Padding(8) };
        readonly FlowLayoutPanel buttons=new FlowLayoutPanel { Dock=DockStyle.Bottom,AutoSize=true,WrapContents=true };
        readonly Action<string> log;
        readonly Action core,lockVault;
        readonly TextBox history=new TextBox {Dock=DockStyle.Bottom,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Height=90};
        string lastResult;
        List<ComponentVersionInfo> rows;
        ComponentRelease release;
        string checkedSource;
        bool busy,closeRequested;
        CancellationTokenSource cancellation;
        Button download;
        public ComponentUpdatesDialog(Action<string> logger,Action coreUpdate,Action lockAction) {
            log=logger; core=coreUpdate; lockVault=lockAction;
            Text="WinUp — обновления компонентов"; StartPosition=FormStartPosition.CenterParent;
            Size=new Size(1160,650); MinimumSize=new Size(850,500); Font=new Font("Segoe UI",9);
            list.Columns.Add("Компонент",210); list.Columns.Add("Сейчас используется",140);list.Columns.Add("После перезапуска",145);list.Columns.Add("У разработчика",135); list.Columns.Add("Состояние",500);
            Controls.Add(list);Controls.Add(history); Controls.Add(state); state.Dock=DockStyle.Top; Controls.Add(buttons);
            Add("Проверить",Check);
            Add("Источник пакетов…",Configure);
            download=Add("Скачать комплект",Download);
            Add("Установить из файла…",Import);
            Add("Обновить KeePass",delegate { core(); RefreshRows();var row=rows.First(r=>r.Id=="keepass");Result(row.Pending==null ? "Проверка KeePass закончена. Работающее ядро: "+row.Installed+"." : "KeePass "+row.Pending+" подготовлен. Перезапустите WinUp; сейчас используется "+row.Installed+"."); });
            Add("Обновить WinFsp",UpdateDriver);
            Add("Откат…",Rollback);
            Add("Перезапустить",delegate { CoreUpdate.RestartPendingFlag=true; Close(); });
            Add("Закрыть",Close);
            FormClosing+=(s,e)=> { if(busy) {e.Cancel=true;closeRequested=true;if(cancellation!=null)cancellation.Cancel();state.Text="Завершаю операцию…";} };
            RefreshRows();
            Appearance.Apply(this);
        }
        Button Add(string text,Action action) { var button=new Button { Text=text,AutoSize=true,Margin=new Padding(4) }; button.Click+=(s,e)=>action(); buttons.Controls.Add(button); return button; }
        void RefreshRows() {
            var previous=rows;rows=ComponentInventory.Rows();
            foreach(var row in rows) {var old=previous==null ? null : previous.FirstOrDefault(x=>x.Id==row.Id);if(old!=null && old.Latest!=null){row.Latest=old.Latest;row.Source=old.Source;ComponentInventory.Availability(row);}}
            list.Items.Clear(); foreach(var row in rows) list.Items.Add(new ListViewItem(new[] {row.Name,row.Installed,row.Pending ?? "—",row.Latest ?? "—",row.Status}) {Tag=row,ToolTipText=row.Name+"\nСейчас: "+row.Installed+"\nПосле перезапуска: "+(row.Pending ?? "—")+"\n"+row.Status});
            ComponentState selected;
            try { selected=ComponentResources.Store.State(); }
            catch(Exception ex) { state.Text="Используется проверенный комплект. Состояние обновлений повреждено: "+ex.Message; download.Enabled=false; return; }
            string pending=selected.active!=ComponentResources.CurrentId ? rows.Any(r=>r.Pending!=null) ? " Выбран другой проверенный комплект: применится после перезапуска." : " Выбранный комплект не подтверждён для этой версии WinUp." : "";
            state.Text=(ComponentResources.CurrentId==null ? "Используется встроенный комплект." : "Используется подписанный комплект №"+ComponentResources.Current.sequence+".")+pending+
                "\n"+SourceDescription()+
                (ComponentResources.Note==null ? "" : "\n"+ComponentResources.Note)+(lastResult==null ? "" : "\nРезультат: "+lastResult);
            download.Enabled=release!=null && release.sequence>selected.highest;
        }
        string SourceDescription() {
            try { string source=ComponentFeed.Source; return source.Length==0 ? "Источник пакетов WinUp не настроен. Проверка официальных версий работает отдельно; комплект можно установить из файла." : "Источник пакетов: "+source; }
            catch(Exception ex) { return "Источник пакетов недоступен: "+ex.Message; }
        }
        void EnableDownload() { try { download.Enabled=release!=null && release.sequence>ComponentResources.Store.State().highest; } catch { download.Enabled=false; } }
        void Change(ComponentVersionInfo row) {
            if(IsDisposed) return;
            var item=list.Items.Cast<ListViewItem>().First(x=>ReferenceEquals(x.Tag,row)); item.SubItems[3].Text=row.Latest ?? "—"; item.SubItems[4].Text=row.Status;item.ToolTipText=row.Name+"\nСейчас: "+row.Installed+"\nПосле перезапуска: "+(row.Pending ?? "—")+"\nУ разработчика: "+(row.Latest ?? "—")+"\n"+row.Status+"\n"+row.Source;
        }
        void Result(string text) {lastResult=text;state.Text=text;history.AppendText(DateTime.Now.ToString("HH:mm:ss")+"  "+text+Environment.NewLine);if(log!=null)log(text);}
        void PackageProgress(string text) {
            Invoke((MethodInvoker)delegate {Result(text);foreach(var row in rows.Where(r=>r.Id!="keepass" && r.Id!="winfsp")) {row.Status=text;Change(row);} });
        }
        async void Run(Action<CancellationToken> action,Action done=null) {
            if(busy) return; busy=true; cancellation=new CancellationTokenSource(); foreach(Control control in buttons.Controls) control.Enabled=false;
            Result("Операция выполняется…");
            try { await Task.Run(delegate { action(cancellation.Token); }); if(done!=null) done(); }
            catch(OperationCanceledException) { RefreshRows();Result("Операция отменена. Текущий комплект продолжает работать."); }
            catch(Exception ex) { RefreshRows();Result("Операция не выполнена: "+ex.Message);MessageBox.Show(this,ex.Message,Text,MessageBoxButtons.OK,MessageBoxIcon.Warning); }
            finally { cancellation.Dispose(); cancellation=null; busy=false; foreach(Control control in buttons.Controls) control.Enabled=true; EnableDownload();if(closeRequested)Close(); }
        }
        void Check() {
            try { checkedSource=ComponentFeed.Source; } catch(Exception ex) { MessageBox.Show(this,ex.Message,Text); return; } release=null;
            Run(delegate(CancellationToken token) {
                ComponentInventory.Check(rows,delegate(ComponentVersionInfo row) { token.ThrowIfCancellationRequested(); Invoke((MethodInvoker)delegate { Change(row);state.Text="Проверка: "+row.Name+" — "+row.Status; }); },token);
                if(checkedSource.Length>0) release=ComponentFeed.Check(checkedSource,token);
            },delegate {
                Result(release==null ? "Проверка версий завершена. Комплект не найден; новые выпуски у разработчиков сами по себе не устанавливаются в WinUp." :
                    release.sequence>ComponentResources.Store.State().highest ? "Доступен подписанный комплект №"+release.sequence+". Нажмите «Скачать комплект»." :
                    rows.Any(r=>r.Pending!=null) ? "Обновление уже подготовлено. Перезапустите WinUp, чтобы оно начало использоваться." : "Проверка завершена. Новый комплект WinUp не обнаружен.");
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
                Run(token=>{PackageProgress("Проверяю подпись, целостность и совместимость выбранного файла…");using(var inspected=ComponentResources.Store.Inspect(path)) {} token.ThrowIfCancellationRequested();},delegate {
                    RefreshRows();Result("Файл проверен: подпись, целостность и совместимость подтверждены.");
                    if(MessageBox.Show(this,"Пакет проверен. Подготовить его для применения после перезапуска?",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes) {Result("Подготовка отменена пользователем. Работающий комплект не менялся.");return;}
                    // Queue outside the completion callback, while Run is still marked busy.
                    BeginInvoke((MethodInvoker)delegate { Run(delegate {PackageProgress("Сохраняю проверенный комплект для перезапуска…");ComponentResources.Store.Install(path); },Installed); });
                });
            }
        }
        void Download() {
            if(release==null || MessageBox.Show(this,"Скачать проверенный комплект №"+release.sequence+" и подготовить его к перезапуску?",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
            var selected=release; string source=checkedSource;
            Run(token=>ComponentFeed.Install(selected,source,token,PackageProgress),Installed);
        }
        void Installed() { Result("Комплект проверен и подготовлен. Текущая работающая версия изменится после перезапуска WinUp; подготовленные версии показаны в таблице."); release=null; RefreshRows(); }
        void Rollback() {
            if(MessageBox.Show(this,"Вернуться к предыдущему проверенному комплекту? Изменение применится после перезапуска; данные хранилищ не меняются.",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
            Run(delegate { ComponentResources.Store.Rollback(); },delegate {Result("Откат подготовлен. Предыдущий комплект начнёт работать после перезапуска WinUp.");RefreshRows();});
        }
        void UpdateDriver() {
            if(MessageBox.Show(this,"Проверить и установить официальный WinFsp? Файловые хранилища будут закрыты. Windows запросит права администратора; может потребоваться перезагрузка Windows.",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
            lockVault(); string result=null;
            Run(token=>result=WinFspDriver.UpdateOfficial(token),delegate { RefreshRows();Result(result); MessageBox.Show(this,result,Text); });
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

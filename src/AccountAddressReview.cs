using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinUp {
    internal sealed class AddressReviewRow {
        internal LoginEntry Entry;
        internal string Message,Target,LoginUrl,AppTarget;
        internal string SiteResult,LoginResult,LoginHint,SiteCheckedAddress,LoginCheckedAddress;
        internal DateTime? CheckedAt;
        internal string SiteAddress {get{return Entry.Kind=="app"?"":FixTarget?Target:Entry.Target;}}
        internal string LoginAddress {get{return Entry.Kind=="app"?"":FixLogin?LoginUrl:Entry.LoginUrl;}}
        internal bool FixTarget,FixLogin,FixApp;
        internal bool CanFix {get{return FixTarget||FixLogin||FixApp;}}
        internal string Proposal {get{return string.Join("; ",new[]{FixTarget?"Сайт → "+Target:null,FixLogin?"Вход → "+LoginUrl:null,FixApp?"Приложение → "+AppTarget:null}.Where(x=>x!=null));}}
        internal void Apply(){if(FixTarget)Entry.Target=Target;if(FixLogin)Entry.LoginUrl=LoginUrl;if(FixApp){if(Entry.Kind=="app")Entry.Target=AppTarget;else Entry.AppTarget=AppTarget;if(LocalApplications.IsShell(AppTarget))Entry.Args="";}}
    }
    internal static class AccountAddressReview {
        internal static AddressReviewRow Inspect(LoginEntry entry,IEnumerable<LocalApplication> apps){
            var row=new AddressReviewRow{Entry=entry};var messages=new List<string>();
            if(entry.Kind!="app"){
                string target=(entry.Target??"").Trim();
                if(target.Length>0&&!target.Contains("://")){
                    string normalized="https://"+target;
                    if(LoginProfiles.Origin(normalized)!=null){row.FixTarget=true;row.Target=normalized;target=normalized;messages.Add("В адресе сайта нет https://");}
                }
                if(LoginProfiles.Origin(target)==null)messages.Add("Адрес сайта пустой или не поддерживается для автовхода");
                else{
                    string origin=LoginProfiles.Origin(target);
                    var expected=LoginProfiles.All.FirstOrDefault(p=>p.Id==entry.LoginProfile)??LoginProfiles.All.FirstOrDefault(p=>p.Id==AppStore.TemplateName(entry.Name));
                    if(expected!=null&&!expected.Origins.Contains(origin,StringComparer.OrdinalIgnoreCase)&&!expected.Sites.Contains(origin,StringComparer.OrdinalIgnoreCase))messages.Add("Адрес сайта отличается от шаблона «"+expected.Id+"»: проверьте домен вручную");
                    var draft=new LoginEntry{Name=entry.Name,Target=target,LoginUrl=entry.LoginUrl,LoginProfile=entry.LoginProfile};
                    var profile=LoginProfiles.Resolve(draft);
                    if(profile==null)messages.Add("Адрес входа не принадлежит сайту или разрешённому сервису входа");
                    else{
                        string saved=(entry.LoginUrl??"").Trim();
                        if(profile.Id!="custom"&&(saved.Length==0||!string.Equals(saved.TrimEnd('/'),profile.LoginUrl.TrimEnd('/'),StringComparison.Ordinal))){
                            row.FixLogin=true;row.LoginUrl=profile.LoginUrl;messages.Add("Есть адрес входа из правил сервиса");
                        }
                        if(saved.Length==0&&profile.Id=="custom")messages.Add("Страница входа не задана: будет открыт адрес сайта; укажите путь к форме входа");
                        if(profile.Mode=="manual"||profile.Mode=="none")messages.Add("Сервис требует ручной вход: "+profile.Note);
                        row.LoginHint="Автоввод: "+(profile.Mode=="manual"||profile.Mode=="none"?"вход вручную":"правила «"+profile.Id+"»")+". "+profile.Note+"\r\nРазрешённые адреса для автоввода: "+string.Join(", ",profile.Origins);
                    }
                }
            }
            if(entry.Kind=="app"||entry.Kind=="both"){
                string path=entry.Kind=="app"?entry.Target:entry.AppTarget;
                if(!LocalApplications.Exists(path,apps)){
                    messages.Add("Приложение не найдено на этом ПК");
                    var match=LocalApplications.Match(apps,entry.Name,entry.Kind=="both"?entry.Target:"");
                    if(match!=null){row.FixApp=true;row.AppTarget=match.Target;messages.Add("Найден установленный вариант");}
                }
                if(LocalApplications.IsShell(path)&&!string.IsNullOrWhiteSpace(entry.Args))messages.Add("Для приложения Windows нужно очистить параметры запуска");
                if(string.IsNullOrWhiteSpace(entry.Window))messages.Add("Для ввода в приложение нужен заголовок окна");
            }
            if(!string.IsNullOrEmpty(entry.Browser)&&Browsers.Find(entry.Browser)==null)messages.Add("Выбранный браузер не установлен");
            row.Message=messages.Count==0?"Настройки проверены":string.Join(". ",messages);
            return row;
        }
        // Validate and pin public destinations; never follow redirects or send
        // credentials, cookies, or ambient proxy authentication.
        internal static string CheckWeb(string address,CancellationToken cancellation){
            return PublicWebProbe.Check(address,cancellation);
        }
    }
    sealed class AccountAddressDialog:Form,ILockableDialog {
        readonly ListView list=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,CheckBoxes=true,HideSelection=false,ShowItemToolTips=true};
        readonly Label state=new Label{Dock=DockStyle.Bottom,Height=48,Padding=new Padding(6)};
        readonly TextBox details=new TextBox{Dock=DockStyle.Bottom,Multiline=true,ReadOnly=true,Height=170,ScrollBars=ScrollBars.Vertical};
        readonly Func<bool> current;readonly Func<LoginEntry[],bool> apply;readonly Action<LoginEntry> edit;
        readonly Func<string,CancellationToken,string> probe;
        CancellationTokenSource webCancellation;bool loading,busy;
        readonly Button refresh,web,editButton,applyButton,cancel;
        internal AccountAddressDialog(Func<bool> current,Func<LoginEntry[],bool> apply,Action<LoginEntry> edit,Func<IEnumerable<LoginEntry>> entries,Func<string,CancellationToken,string> probe=null){
            this.current=current;this.apply=apply;this.edit=edit;this.probe=probe??AccountAddressReview.CheckWeb;
            Text="Проверка адресов и приложений";Font=new System.Drawing.Font("Segoe UI",9f);Icon=AppIcons.Open;Size=new System.Drawing.Size(1120,720);MinimumSize=new System.Drawing.Size(720,520);StartPosition=FormStartPosition.CenterParent;
            list.Columns.Add("Запись",145);list.Columns.Add("Настройки",230);list.Columns.Add("Сайт",210);list.Columns.Add("Страница входа",210);list.Columns.Add("Исправление",250);
            var bar=new FlowLayoutPanel{Dock=DockStyle.Top,AutoSize=true,Padding=new Padding(4)};
            refresh=Add(bar,"Проверить настройки",async()=>await LoadRows(entries));
            web=Add(bar,"Проверить отмеченные сайты",async()=>await Web());
            cancel=Add(bar,"Остановить проверку",()=>{if(webCancellation!=null){webCancellation.Cancel();cancel.Enabled=false;state.Text="Останавливаем проверку…";}});cancel.Enabled=false;
            Add(bar,"Отметить все / снять",()=>{if(busy)return;bool mark=list.Items.Cast<ListViewItem>().Any(x=>!x.Checked);foreach(ListViewItem item in list.Items)item.Checked=mark;});
            editButton=Add(bar,"Изменить запись…",()=>{if(busy)return;if(list.SelectedItems.Count==0){state.Text="Выделите запись для изменения.";return;}if(current()){edit(((AddressReviewRow)list.SelectedItems[0].Tag).Entry);var ignored=LoadRows(entries);}});
            applyButton=Add(bar,"Применить отмеченные исправления",()=>{if(current()&&!busy){var selected=list.CheckedItems.Cast<ListViewItem>().Select(x=>(AddressReviewRow)x.Tag).Where(x=>x.CanFix).ToArray();if(selected.Length==0){state.Text="Отметьте записи с предлагаемым исправлением.";return;}Pending=selected;try{if(apply(selected.Select(x=>x.Entry).ToArray())){var ignored=LoadRows(entries);}}finally{Pending=null;}}});
            var close=Add(bar,"Закрыть",Close);CancelButton=close;
            list.ItemChecked+=(s,e)=>{if(!loading&&!busy)state.Text="Отмечено: "+list.CheckedItems.Count+". Без галочек проверяются выделенные строки. Исправления применяются отдельной кнопкой.";};
            list.SelectedIndexChanged+=(s,e)=>{if(!loading)ShowDetails(list.SelectedItems.Count==0?null:(AddressReviewRow)list.SelectedItems[0].Tag);};
            state.Text="Выберите записи для проверки сайтов или исправления адресов. Проверка не отправляет пароли и не меняет адреса.";
            Controls.Add(list);Controls.Add(details);Controls.Add(state);Controls.Add(bar);Appearance.WrapLabel(state,40);Appearance.Apply(this);Shown+=async(s,e)=>await LoadRows(entries);
        }
        protected override void OnHandleCreated(EventArgs e){base.OnHandleCreated(e);Win.ApplyCaptureProtection(this);}
        internal AddressReviewRow[] Pending;
        void SetBusy(bool value){busy=value;if(!IsDisposed){refresh.Enabled=web.Enabled=editButton.Enabled=applyButton.Enabled=!value;cancel.Enabled=value&&webCancellation!=null;}}
        Button Add(FlowLayoutPanel bar,string text,Action action){var b=new Button{Text=text,AutoSize=true};b.Click+=(s,e)=>{try{action();}catch(Exception ex){if(!IsDisposed)MessageBox.Show(this,ex.Message,"WinUp");}};bar.Controls.Add(b);return b;}
        void PaintRow(ListViewItem item){var row=(AddressReviewRow)item.Tag;item.SubItems[1].Text=row.Message;item.SubItems[2].Text=row.Entry.Kind=="app"?"—":row.SiteResult??"Не проверено";item.SubItems[3].Text=row.Entry.Kind=="app"?"—":row.LoginResult??"Не проверено";item.SubItems[4].Text=row.Proposal;item.ToolTipText=row.Message;}
        void ShowDetails(AddressReviewRow row){
            if(IsDisposed)return;if(row==null){details.Text="Выделите запись для просмотра адресов и результатов проверки.";return;}
            var entry=row.Entry;
            details.Text="Сайт: "+(entry.Kind=="app"?"не используется":entry.Target)+"\r\nСтраница входа: "+(string.IsNullOrWhiteSpace(entry.LoginUrl)?"не задана":entry.LoginUrl)+"\r\nПриложение: "+(entry.Kind=="app"?entry.Target:entry.AppTarget)+"\r\nНастройки: "+row.Message+
                (string.IsNullOrEmpty(row.Proposal)?"":"\r\nПредлагаемое исправление: "+row.Proposal)+(string.IsNullOrEmpty(row.LoginHint)?"":"\r\n"+row.LoginHint)+
                "\r\nСайт ["+row.SiteAddress+"]: "+(row.SiteResult??"не проверен")+"\r\nСтраница входа ["+row.LoginAddress+"]: "+(row.LoginResult??"не проверена")+
                (row.CheckedAt.HasValue?"\r\nПоследняя проверка: "+row.CheckedAt.Value.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss"):"")+"\r\nСетевой ответ проверяет доступность адреса. Заполнение формы и вход проверяются в браузере с расширением WinUp.";
        }
        async Task LoadRows(Func<IEnumerable<LoginEntry>> entries){
            if(busy||!current()||IsDisposed)return;SetBusy(true);
            try{var apps=await LocalApplications.Available(true);if(IsDisposed||!current())return;loading=true;
                var old=list.Items.Cast<ListViewItem>().Select(x=>(AddressReviewRow)x.Tag).ToDictionary(x=>x.Entry.Id);
                var marked=new HashSet<string>(list.CheckedItems.Cast<ListViewItem>().Select(x=>((AddressReviewRow)x.Tag).Entry.Id));var chosen=new HashSet<string>(list.SelectedItems.Cast<ListViewItem>().Select(x=>((AddressReviewRow)x.Tag).Entry.Id));
                list.BeginUpdate();try{list.Items.Clear();foreach(var entry in entries().Where(x=>x.Kind!="passkey")){
                    var row=AccountAddressReview.Inspect(entry,apps);AddressReviewRow previous;
                    if(old.TryGetValue(entry.Id,out previous)){if(previous.SiteCheckedAddress==row.SiteAddress){row.SiteResult=previous.SiteResult;row.SiteCheckedAddress=previous.SiteCheckedAddress;}if(previous.LoginCheckedAddress==row.LoginAddress){row.LoginResult=previous.LoginResult;row.LoginCheckedAddress=previous.LoginCheckedAddress;}if(row.SiteResult!=null||row.LoginResult!=null)row.CheckedAt=previous.CheckedAt;}
                    var item=new ListViewItem(new[]{entry.Name,"","","",""}){Tag=row,Checked=marked.Contains(entry.Id)};PaintRow(item);list.Items.Add(item);item.Selected=chosen.Contains(entry.Id);
                }}finally{list.EndUpdate();}
                if(list.SelectedItems.Count==0&&list.Items.Count>0)list.Items[0].Selected=true;
                ShowDetails(list.SelectedItems.Count==0?null:(AddressReviewRow)list.SelectedItems[0].Tag);
                state.Text="Проверено записей на ПК: "+list.Items.Count+". Проверка сайтов показывает отдельные результаты сайта и страницы входа. Предлагаемые адреса проверяются до применения.";
            }catch(Exception ex){if(!IsDisposed)state.Text=ex.Message;}finally{loading=false;SetBusy(false);}
        }
        async Task Web(){
            if(busy||!current())return;var chosen=list.CheckedItems.Count>0?list.CheckedItems.Cast<ListViewItem>():list.SelectedItems.Cast<ListViewItem>();var selected=chosen.Where(x=>((AddressReviewRow)x.Tag).Entry.Kind!="app").ToArray();
            if(selected.Length==0){state.Text="Отметьте сайты галочками или выделите строки для проверки (Ctrl / Shift).";return;}
            webCancellation=new CancellationTokenSource();var token=webCancellation.Token;SetBusy(true);int completed=0;
            var cache=new Dictionary<string,string>(StringComparer.Ordinal);
            try{foreach(var item in selected){token.ThrowIfCancellationRequested();if(!current()||IsDisposed)return;var row=(AddressReviewRow)item.Tag;
                foreach(bool login in new[]{false,true}){
                    string url=login?row.LoginAddress:row.SiteAddress;string response;
                    if(string.IsNullOrWhiteSpace(url))response="Адрес не задан";
                    else if(!cache.TryGetValue(url,out response)){
                        state.Text="Запись "+(completed+1)+" из "+selected.Length+": "+row.Entry.Name+" — "+(login?"страница входа":"сайт");
                        response=await Task.Run(()=>probe(url,token));token.ThrowIfCancellationRequested();if(IsDisposed||!current())return;cache[url]=response;
                    }
                    if(login){row.LoginResult=response;row.LoginCheckedAddress=url;}else{row.SiteResult=response;row.SiteCheckedAddress=url;}row.CheckedAt=DateTime.UtcNow;PaintRow(item);
                    if(list.SelectedItems.Count==0||list.SelectedItems[0]==item)ShowDetails(row);
                }completed++;
            }state.Text="Проверено записей: "+completed+". Результаты сохранены в столбцах «Сайт» и «Страница входа». HTTP-ответ не подтверждает работу автоввода.";
            }catch(OperationCanceledException){if(!IsDisposed)state.Text="Проверка остановлена. Полностью проверено записей: "+completed+" из "+selected.Length+". Полученные результаты сохранены.";}
            catch(Exception ex){if(!IsDisposed)state.Text=ex.Message;}finally{var source=webCancellation;webCancellation=null;source.Dispose();SetBusy(false);}
        }
        protected override void Dispose(bool disposing){if(disposing&&webCancellation!=null)webCancellation.Cancel();base.Dispose(disposing);}
    }
    partial class MainForm {
        void ReviewAccountAddresses(){
            if(!NeedVault())return;var original=vault;AccountAddressDialog dialog=null;
            using(dialog=new AccountAddressDialog(()=>vault==original,entries=>{
                if(vault!=original||entries.Any(e=>!original.Entries.Contains(e)))return false;
                var changes=dialog.Pending;if(changes==null)return false;
                var previous=entries.Select(e=>new{Entry=e,e.Target,e.LoginUrl,e.AppTarget,e.Args}).ToArray();
                foreach(var change in changes)change.Apply();
                if(SaveVault()){PwLog("Исправлены адреса / приложения: "+entries.Length+".");return true;}
                foreach(var old in previous){old.Entry.Target=old.Target;old.Entry.LoginUrl=old.LoginUrl;old.Entry.AppTarget=old.AppTarget;old.Entry.Args=old.Args;}return false;
            },entry=>EditEntry(entry),()=>original.Entries)){dialog.ShowDialog(this);}
        }
    }
}

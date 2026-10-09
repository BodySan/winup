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
                    if(expected!=null&&!expected.Origins.Contains(origin,StringComparer.OrdinalIgnoreCase))messages.Add("Адрес сайта отличается от шаблона «"+expected.Id+"»: проверьте домен вручную");
                    var draft=new LoginEntry{Name=entry.Name,Target=target,LoginUrl=entry.LoginUrl,LoginProfile=entry.LoginProfile};
                    var profile=LoginProfiles.Resolve(draft);
                    if(profile==null)messages.Add("Адрес входа не принадлежит сайту или разрешённому сервису входа");
                    else{
                        string saved=(entry.LoginUrl??"").Trim();
                        if(saved.Length==0||!string.Equals(saved.TrimEnd('/'),profile.LoginUrl.TrimEnd('/'),StringComparison.Ordinal)){
                            row.FixLogin=true;row.LoginUrl=profile.LoginUrl;messages.Add("Есть адрес входа из правил сервиса");
                        }
                        if(profile.Mode=="manual"||profile.Mode=="none")messages.Add("Сервис требует ручной вход: "+profile.Note);
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
            row.Message=messages.Count==0?"Локальная проверка пройдена; доступность сайта ещё не проверена":string.Join(". ",messages);
            return row;
        }
        // A status check never sends credentials, cookies, or changes a stored address.
        internal static string CheckWeb(string address,CancellationToken cancellation){
            Uri uri;
            if(!Uri.TryCreate(address,UriKind.Absolute,out uri)||LoginProfiles.Origin(address)==null)return "Неверный адрес";
            try{
                ServicePointManager.SecurityProtocol|=(SecurityProtocolType)3072;
                var request=(HttpWebRequest)WebRequest.Create(uri);request.Method="GET";request.AllowAutoRedirect=false;
                request.Timeout=7000;request.ReadWriteTimeout=7000;request.UserAgent="WinUp address check";request.KeepAlive=false;
                request.UseDefaultCredentials=false;request.CookieContainer=null;
                using(cancellation.Register(request.Abort)){
                    HttpWebResponse response;
                    try{response=(HttpWebResponse)request.GetResponse();}catch(WebException ex){response=ex.Response as HttpWebResponse;if(response==null)throw;}
                    using(response){
                        int code=(int)response.StatusCode;
                        if(code>=300&&code<400)return "HTTP "+code+": переход на "+(response.Headers["Location"]??"другую страницу")+" — проверьте в браузере";
                        if(code==401||code==403||code==429)return "HTTP "+code+": сайт ограничил проверку; адрес может работать в браузере";
                        if(code>=400)return "HTTP "+code+": возможная ошибка адреса";
                        return "HTTP "+code+": адрес отвечает; наличие формы входа проверьте в браузере";
                    }
                }
            }catch(WebException){return cancellation.IsCancellationRequested?"Проверка отменена":"Не удалось подключиться: проверьте сеть и адрес";}
        }
    }
    sealed class AccountAddressDialog:Form,ILockableDialog {
        readonly ListView list=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,CheckBoxes=true,HideSelection=false};
        readonly Label state=new Label{Dock=DockStyle.Bottom,Height=48,Padding=new Padding(6)};
        readonly TextBox details=new TextBox{Dock=DockStyle.Bottom,Multiline=true,ReadOnly=true,Height=112,ScrollBars=ScrollBars.Vertical};
        readonly Func<bool> current;readonly Func<LoginEntry[],bool> apply;readonly Action<LoginEntry> edit;
        readonly CancellationTokenSource cancellation=new CancellationTokenSource();bool loading,busy;
        readonly Button refresh,web;
        internal AccountAddressDialog(Func<bool> current,Func<LoginEntry[],bool> apply,Action<LoginEntry> edit,Func<IEnumerable<LoginEntry>> entries){
            this.current=current;this.apply=apply;this.edit=edit;
            Text="Проверка адресов и приложений";Size=new System.Drawing.Size(1050,670);MinimumSize=new System.Drawing.Size(720,500);StartPosition=FormStartPosition.CenterParent;
            list.Columns.Add("Запись",155);list.Columns.Add("Проверка",390);list.Columns.Add("Предлагаемое исправление",430);
            var bar=new FlowLayoutPanel{Dock=DockStyle.Top,AutoSize=true,Padding=new Padding(4)};
            refresh=Add(bar,"Проверить заново",async()=>await LoadRows(entries));
            web=Add(bar,"Проверить выбранные сайты",async()=>await Web());
            Add(bar,"Изменить запись…",()=>{if(list.SelectedItems.Count==0){state.Text="Выделите запись для изменения.";return;}if(current()){edit(((AddressReviewRow)list.SelectedItems[0].Tag).Entry);var ignored=LoadRows(entries);}});
            Add(bar,"Применить отмеченные исправления",()=>{if(current()&&!busy){var selected=list.CheckedItems.Cast<ListViewItem>().Select(x=>(AddressReviewRow)x.Tag).Where(x=>x.CanFix).ToArray();if(selected.Length==0){state.Text="Отметьте записи с предлагаемым исправлением.";return;}Pending=selected;if(apply(selected.Select(x=>x.Entry).ToArray())){var ignored=LoadRows(entries);}Pending=null;}});
            Add(bar,"Закрыть",Close);
            list.ItemCheck+=(s,e)=>{if(loading||!((AddressReviewRow)list.Items[e.Index].Tag).CanFix)e.NewValue=CheckState.Unchecked;};
            list.SelectedIndexChanged+=(s,e)=>{if(list.SelectedItems.Count==0){details.Text="Выделите запись: здесь показаны полные адреса и предлагаемые изменения.";return;}var row=(AddressReviewRow)list.SelectedItems[0].Tag;var entry=row.Entry;details.Text="Сайт: "+(entry.Kind=="app"?"не используется":entry.Target)+"\r\nАдрес входа: "+entry.LoginUrl+"\r\nПриложение: "+(entry.Kind=="app"?entry.Target:entry.AppTarget)+"\r\nИсправление: "+row.Proposal+"\r\n"+list.SelectedItems[0].SubItems[1].Text;};
            state.Text="Проверка на ПК не отправляет пароли. Сетевой запрос выполняется только кнопкой для выбранных строк. Галочки — исправления; выделение строки — проверка сайта. Ошибка HTTP не доказывает, что сайт не работает.";
            Controls.Add(list);Controls.Add(details);Controls.Add(state);Controls.Add(bar);Appearance.Apply(this);Shown+=async(s,e)=>await LoadRows(entries);
        }
        internal AddressReviewRow[] Pending;
        Button Add(FlowLayoutPanel bar,string text,Action action){var b=new Button{Text=text,AutoSize=true};b.Click+=(s,e)=>{try{action();}catch(Exception ex){if(!IsDisposed)MessageBox.Show(this,ex.Message,"WinUp");}};bar.Controls.Add(b);return b;}
        async Task LoadRows(Func<IEnumerable<LoginEntry>> entries){
            if(busy||!current()||IsDisposed)return;busy=true;refresh.Enabled=web.Enabled=false;
            try{var apps=await LocalApplications.Available(true);if(IsDisposed||!current())return;loading=true;list.Items.Clear();
                foreach(var entry in entries().Where(x=>x.Kind!="passkey")){var row=AccountAddressReview.Inspect(entry,apps);list.Items.Add(new ListViewItem(new[]{entry.Name,row.Message,row.Proposal}){Tag=row});}
                state.Text="Проверено записей: "+list.Items.Count+". Исправления сначала показываются в последнем столбце. Пароли и логины не меняются. Сетевые проверки — отдельно по выделенным строкам.";
            }catch(Exception ex){if(!IsDisposed)state.Text=ex.Message;}finally{loading=false;busy=false;if(!IsDisposed)refresh.Enabled=web.Enabled=true;}
        }
        async Task Web(){
            if(busy||!current())return;var selected=list.SelectedItems.Cast<ListViewItem>().Where(x=>((AddressReviewRow)x.Tag).Entry.Kind!="app").ToArray();
            if(selected.Length==0){state.Text="Выделите строки сайтов для проверки (Ctrl / Shift).";return;}busy=true;refresh.Enabled=web.Enabled=false;
            try{foreach(var item in selected){var row=(AddressReviewRow)item.Tag;var urls=new[]{row.FixTarget?row.Target:row.Entry.Target,row.FixLogin?row.LoginUrl:row.Entry.LoginUrl}.Where(x=>!string.IsNullOrWhiteSpace(x)).Distinct().ToArray();var results=new List<string>();foreach(string url in urls){string response=await Task.Run(()=>AccountAddressReview.CheckWeb(url,cancellation.Token));if(IsDisposed||!current()||cancellation.IsCancellationRequested)return;results.Add(url+": "+response);}item.SubItems[1].Text=row.Message+" | "+string.Join(" | ",results);details.Text=string.Join("\r\n",results);state.Text="Проверено: "+row.Entry.Name+". HTTP-ответ не проверяет заполнение формы.";}}
            catch(Exception ex){if(!IsDisposed)state.Text=ex.Message;}finally{busy=false;if(!IsDisposed)refresh.Enabled=web.Enabled=true;}
        }
        protected override void Dispose(bool disposing){if(disposing){cancellation.Cancel();}base.Dispose(disposing);}
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

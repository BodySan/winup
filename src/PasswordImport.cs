using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace WinUp {
    internal sealed class PasswordImportRow {
        internal LoginEntry Entry;internal OtpEntry Otp;internal string Status;internal bool Selectable=true,DefaultSelected=true,Adopted;
    }
    internal sealed class PasswordImportResult:IDisposable {
        internal string Format;internal readonly List<PasswordImportRow> Rows=new List<PasswordImportRow>();
        public void Dispose(){foreach(var row in Rows)if(!row.Adopted){if(row.Entry!=null)row.Entry.ClearSecrets();if(row.Otp!=null)row.Otp.ClearSecret();}}
    }
    internal static partial class PasswordImport {
        internal static PasswordImportResult Read(string path,IEnumerable<LoginEntry> existing,IEnumerable<OtpEntry> existingOtp=null){
            using(var lease=SourceLease.Acquire(path,false)) {
                byte[] bytes=SafeStorage.ReadBounded(path,8*1024*1024);string text=null;
                try{text=new UTF8Encoding(false,true).GetString(bytes);return Parse(text,existing,existingOtp);}finally{Array.Clear(bytes,0,bytes.Length);Secure.Wipe(text);}
            }
        }
        internal static PasswordImportResult Parse(string text,IEnumerable<LoginEntry> existing,IEnumerable<OtpEntry> existingOtp=null) {
            if(text==null||text.Length>8*1024*1024)throw new IOException("CSV слишком большой.");
            var result=new PasswordImportResult();
            List<string[]> rows=null;
            try {
                rows=Csv(text);if(rows.Count<1)throw new IOException("CSV пуст.");
                var headers=new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
                for(int i=0;i<rows[0].Length;i++){string name=rows[0][i].Trim().TrimStart('\uFEFF');if(!headers.TryAddCompat(name,i))throw new IOException("В CSV повторяется название столбца.");}
                int url=Index(headers,"url"),user=Index(headers,"username"),password=Index(headers,"password");
                if(url<0||user<0||password<0)throw new IOException("Нужны столбцы URL, Username и Password. Поддерживаются CSV Google и Apple.");
                int title=Index(headers,"title");if(title<0)title=Index(headers,"name");int notes=Index(headers,"notes");if(notes<0)notes=Index(headers,"note");int otp=Index(headers,"otpauth"),custom=Index(headers,"custom_fields"),category=Index(headers,"category"),pinned=Index(headers,"pinned"),warning=Index(headers,"import_warning");
                result.Format=headers.ContainsKey("title")?"Apple «Пароли» / Safari":"Google Password Manager / Chromium";
                var known=existing.Where(x=>x.Kind!="passkey").ToList();var accepted=new List<LoginEntry>();
                for(int n=1;n<rows.Count;n++) {
                    string[] fields=rows[n];var row=new PasswordImportRow();result.Rows.Add(row);
                    if(fields.Length!=headers.Count){row.Selectable=false;row.DefaultSelected=false;row.Status="Строка "+(n+1)+": неверное число столбцов";Clear(fields);continue;}
                    string address=fields[url].Trim();Uri uri;
                    if(!Uri.TryCreate(address,UriKind.Absolute,out uri)||(uri.Scheme!="https"&&uri.Scheme!="http")||uri.UserInfo!=""){
                        row.Selectable=false;row.DefaultSelected=false;row.Status="Строка "+(n+1)+": не поддерживается адрес приложения или сайта";Clear(fields);continue;
                    }
                    if(fields[password].Length==0){row.Selectable=false;row.DefaultSelected=false;row.Status="Строка "+(n+1)+": отсутствует обычный пароль; passkey через CSV не переносится";Clear(fields);continue;}
                    var entry=new LoginEntry{Id=AppStore.NewId(),Kind="site",Name=Copy(title>=0&&!string.IsNullOrWhiteSpace(fields[title])?fields[title]:uri.Host),
                        Target=uri.GetLeftPart(UriPartial.Authority)+"/",LoginUrl=Copy(address),Login=Copy(fields[user]),Password=fields[password],Notes=notes<0?"":Copy(fields[notes]),AutoEnter=false};row.Entry=entry;
                    if(custom>=0&&!string.IsNullOrEmpty(fields[custom]))ReadImportedFields(entry,fields[custom]);
                    if(category>=0)entry.Category=Copy(fields[category]);if(pinned>=0)entry.Pinned=fields[pinned]=="1"||fields[pinned].Equals("true",StringComparison.OrdinalIgnoreCase);
                    if(otp>=0&&!string.IsNullOrWhiteSpace(fields[otp])) {
                        var warnings=new List<string>();row.Otp=OtpImport.FromUri(fields[otp],warnings);
                        if(row.Otp==null){row.Selectable=false;row.DefaultSelected=false;row.Status="Строка "+(n+1)+": не удалось перенести 2FA; запись не выбрана";}
                        else{row.Otp.Id=AppStore.NewId();entry.TwoFa="link";entry.OtpId=row.Otp.Id;}
                    }
                    var matches=known.Concat(accepted).Where(x=>SameAccount(x,entry)).ToList();
                    var identical=matches.Where(x=>x.UsePassword(a=>entry.UsePassword(b=>a==b))).ToList();
                    if(identical.Count>0) {
                        var linked=(existingOtp??new OtpEntry[0]).Concat(result.Rows.Where(x=>x!=row&&x.Otp!=null).Select(x=>x.Otp));
                        bool extra=row.Otp!=null&&!identical.Any(x=>linked.Any(o=>o.Id==x.OtpId&&SameOtp(o,row.Otp)))||(!string.IsNullOrEmpty(entry.Notes)&&!identical.Any(x=>x.Notes==entry.Notes))||entry.CustomFields.Any(f=>!identical.Any(x=>x.CustomFields.Any(g=>g.Name==f.Name&&f.UseValue(v=>g.UseValue(w=>v==w)))));
                        row.DefaultSelected=false;
                        if(extra){row.Status="Пароль совпадает, но есть новые поля / заметки / 2FA: можно добавить отдельно";}
                        else{row.Selectable=false;row.Status="Дубль: пропустить — "+identical[0].Name;}
                    }
                    else if(matches.Count>0){row.DefaultSelected=false;row.Status="Другой пароль у этого аккаунта: можно добавить отдельной записью";}
                    else if(row.Status==null){row.Status="Новая запись"+(row.Otp==null?"":" + 2FA");}
                    if(warning>=0&&!string.IsNullOrEmpty(fields[warning])){row.Status+=". "+fields[warning];row.DefaultSelected=false;}
                    if(row.Selectable)accepted.Add(entry);Clear(fields);
                }
                return result;
            }catch{result.Dispose();throw;}finally{if(rows!=null)foreach(string[] row in rows)Clear(row);}
        }
        static string Copy(string value){return new string(value.ToCharArray());}
        static bool SameOtp(OtpEntry a,OtpEntry b){return a.Algorithm==b.Algorithm&&a.Digits==b.Digits&&a.Period==b.Period&&a.UseSecret(x=>b.UseSecret(y=>x==y));}
        static string IdentityService(Uri uri){
            if(uri.Scheme!="https"||uri.Port!=443||uri.UserInfo.Length!=0)return null;
            string host=uri.Host.ToLowerInvariant();
            if(new[]{"google.com","www.google.com","accounts.google.com","myaccount.google.com","mail.google.com","drive.google.com","calendar.google.com","photos.google.com","keep.google.com","meet.google.com","contacts.google.com","youtube.com","www.youtube.com","studio.youtube.com"}.Contains(host))return "google";
            if(new[]{"icloud.com","www.icloud.com","account.apple.com","appleid.apple.com","idmsa.apple.com"}.Contains(host))return "apple";
            return null;
        }
        internal static bool SameAccount(LoginEntry a,LoginEntry b){Uri ua,ub;return a.Kind!="app"&&b.Kind!="app"&&Uri.TryCreate(a.Target,UriKind.Absolute,out ua)&&Uri.TryCreate(b.Target,UriKind.Absolute,out ub)&&
            (ua.Scheme=="http"||ua.Scheme=="https")&&(ub.Scheme=="http"||ub.Scheme=="https")&&
            ((string.Equals(ua.Host,ub.Host,StringComparison.OrdinalIgnoreCase)&&ua.Port==ub.Port)||(IdentityService(ua)!=null&&IdentityService(ua)==IdentityService(ub)))&&
            (string.Equals(a.Login??"",b.Login??"",StringComparison.Ordinal)||(!string.IsNullOrEmpty(a.Login2)&&a.Login2==b.Login));}
        static bool TryAddCompat(this Dictionary<string,int> map,string key,int value){if(map.ContainsKey(key))return false;map.Add(key,value);return true;}
        static int Index(Dictionary<string,int> header,string key){int result;return header.TryGetValue(key,out result)?result:-1;}
        static void Clear(string[] fields){foreach(string field in fields)Secure.Wipe(field);}
        internal static List<string[]> Csv(string text,char delimiter=',') {
            var result=new List<string[]>();var fields=new List<string>();var value=new StringBuilder();bool quoted=false,afterQuote=false,fieldStarted=false;
            Action finishField=delegate{fields.Add(value.ToString());value.Clear();afterQuote=false;fieldStarted=false;if(fields.Count>64)throw new IOException("Слишком много столбцов CSV.");};
            Action finishRow=delegate{finishField();if(fields.Any(x=>x.Length>0))result.Add(fields.ToArray());fields.Clear();if(result.Count>10001)throw new IOException("За один импорт — до 10 000 записей.");};
            try {
                for(int i=text.Length>0&&text[0]=='\uFEFF'?1:0;i<text.Length;i++) {
                    char c=text[i];
                    if(quoted){if(c=='"'){if(i+1<text.Length&&text[i+1]=='"'){value.Append('"');i++;}else{quoted=false;afterQuote=true;}}else value.Append(c);}
                    else if(c==delimiter)finishField();
                    else if(c=='\r'||c=='\n'){finishRow();if(c=='\r'&&i+1<text.Length&&text[i+1]=='\n')i++;}
                    else if(c=='"'&&!fieldStarted&&!afterQuote){quoted=true;fieldStarted=true;}
                    else {if(afterQuote||c=='"')throw new IOException("Неверные кавычки в CSV. Повторите экспорт без редактирования файла.");value.Append(c);fieldStarted=true;}
                    if(value.Length>1024*1024)throw new IOException("Поле CSV превышает допустимый размер.");
                }
                if(quoted)throw new IOException("CSV оборван внутри кавычек.");if(value.Length>0||fields.Count>0||fieldStarted||afterQuote)finishRow();return result;
            }finally{for(int i=0;i<value.Length;i++)value[i]='\0';value.Clear();}
        }
    }
    sealed class PasswordImportDialog:Dlg,ILockableDialog {
        readonly ListView list=new ListView{Width=640,Height=280,View=View.Details,CheckBoxes=true,FullRowSelect=true};
        internal IEnumerable<PasswordImportRow> Selected{get{return list.Items.Cast<ListViewItem>().Where(x=>x.Checked&&((PasswordImportRow)x.Tag).Selectable).Select(x=>(PasswordImportRow)x.Tag);}}
        public PasswordImportDialog(PasswordImportResult result):base("Импорт паролей: "+result.Format){
            list.Columns.Add("Название",150);list.Columns.Add("Сайт",150);list.Columns.Add("Логин",150);list.Columns.Add("Результат",400);
            foreach(var row in result.Rows){var entry=row.Entry;var item=new ListViewItem(new[]{entry==null?"":entry.Name,entry==null?"":entry.Target,entry==null?"":entry.Login,row.Status}){Tag=row,Checked=row.Selectable&&row.DefaultSelected};list.Items.Add(item);}
            list.ItemCheck+=(s,e)=>{if(!((PasswordImportRow)list.Items[e.Index].Tag).Selectable)e.NewValue=CheckState.Unchecked;};FullRow(list);
            FullRow(new Label{AutoSize=true,Text="Новых: "+result.Rows.Count(x=>x.Selectable&&x.DefaultSelected)+". Дублей / пропущенных: "+result.Rows.Count(x=>!x.Selectable)+". Требуют выбора: "+result.Rows.Count(x=>x.Selectable&&!x.DefaultSelected)+".\nДубли ищутся в базе и внутри CSV, включая дополнительный логин. Пароли в просмотре скрыты.\nСуществующие записи не перезаписываются. Другой пароль / новые данные можно добавить отдельно.\nCSV / JSON / 1PUX содержат открытые пароли. После успешного переноса удалите экспорт.\nPasskey и вложения не импортируются этим способом. Неподдерживаемые записи показаны в списке."});Buttons();Ok.Text="Импортировать выбранное";
            Ok.Click+=(s,e)=>{if(!Selected.Any()){DialogResult=DialogResult.None;MessageBox.Show(this,"Выберите хотя бы одну новую запись.","WinUp");}};
        }
    }
    partial class MainForm {
        void ImportPasswords(){if(!NeedVault())return;
            using(var picker=new OpenFileDialog{Filter="Экспорт менеджера паролей|*.csv;*.json;*.1pux|Произвольный CSV — выбрать столбцы|*.csv",Title="Выберите экспорт паролей"}){
                var initial=vault;if(picker.ShowDialog(this)!=DialogResult.OK||vault!=initial)return;
                using(var result=PasswordImport.ReadAdvanced(picker.FileName,initial.Entries,initial.Otp,this,picker.FilterIndex==2)){
                    if(result==null||vault!=initial)return;using(var dialog=new PasswordImportDialog(result)){
                    var current=vault;if(dialog.ShowDialog(this)!=DialogResult.OK||vault!=current||current==null)return;
                    var selected=dialog.Selected.ToList();
                    foreach(var row in selected){current.Entries.Add(row.Entry);if(row.Otp!=null)current.Otp.Add(row.Otp);}
                    if(!SaveVault()){foreach(var row in selected){current.Entries.Remove(row.Entry);if(row.Otp!=null)current.Otp.Remove(row.Otp);}return;}
                    foreach(var row in selected)row.Adopted=true;
                    RefreshEntries();RefreshOtp();PwLog("Импортировано записей: "+selected.Count+". Существующие записи сохранены.");
                    MessageBox.Show(this,"Импортировано: "+selected.Count+". Проверьте вход в нужные аккаунты.\nФайл экспорта остался на диске и содержит открытые пароли. Удалите его после проверки.","WinUp");
                }}
            }
        }
    }
}

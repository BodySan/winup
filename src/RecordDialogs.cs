using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace WinUp {
    sealed class SecretFieldsDialog:Dlg,ILockableDialog {
        readonly ListView list=new ListView{View=View.Details,FullRowSelect=true,Height=200,Width=510};
        readonly List<AccountSecretField> fields,source;readonly bool viewOnly;bool transferred;
        internal SecretFieldsDialog(List<AccountSecretField> fields,bool viewOnly=false):base("Дополнительные защищённые поля"){
            source=fields;this.fields=fields.Select(f=>f.Copy()).ToList();this.viewOnly=viewOnly;Note("Значения хранятся зашифрованными в базе. Скопированное значение очищается из буфера через 30 секунд.");
            list.Columns.Add("Поле",320);list.Columns.Add("Значение",170);Row("Поля:",list);
            var bar=new FlowLayoutPanel{AutoSize=true};Row("Действия:",bar);
            Add(bar,viewOnly?"Посмотреть…":"Изменить…",Edit);Add(bar,"Скопировать",()=>{var field=Selected();if(field!=null)field.UseResolvedValue(v=>{SecureClip.Copy(v);return 0;});});
            if(!viewOnly){Add(bar,"Добавить…",()=>EditField(null));Add(bar,"Удалить",()=>{var field=Selected();if(field!=null){this.fields.Remove(field);field.Clear();Refresh();}});}
            Buttons();if(viewOnly){Ok.Text="Закрыть";Cancel.Visible=false;}Refresh();
        }
        protected override void OnFormClosed(FormClosedEventArgs e){if(!viewOnly&&DialogResult==DialogResult.OK){foreach(var field in source)field.Clear();source.Clear();source.AddRange(fields);transferred=true;}base.OnFormClosed(e);}
        protected override void Dispose(bool disposing){if(disposing&&!transferred)foreach(var field in fields)field.Clear();base.Dispose(disposing);}
        static void Add(FlowLayoutPanel panel,string title,Action action){var button=new Button{Text=title,AutoSize=true};button.Click+=(s,e)=>{try{action();}catch(Exception ex){MessageBox.Show(button.FindForm(),ex.Message,"WinUp");}};panel.Controls.Add(button);}
        AccountSecretField Selected(){return list.SelectedItems.Count==0?null:(AccountSecretField)list.SelectedItems[0].Tag;}
        new void Refresh(){list.Items.Clear();foreach(var field in fields)list.Items.Add(new ListViewItem(new[]{field.Name,"••••••••"}){Tag=field});}
        void Edit(){var field=Selected();if(field!=null)EditField(field);}
        void EditField(AccountSecretField field){
            using(var dialog=new SecretFieldDialog(field,viewOnly,fields)){if(dialog.ShowDialog(this)!=DialogResult.OK||viewOnly)return;
                if(field==null){if(fields.Count>=128)throw new InvalidOperationException("Не больше 128 дополнительных полей в записи.");field=new AccountSecretField();fields.Add(field);}
                field.Name=dialog.FieldName;field.Value=dialog.Value;Refresh();}
        }
    }
    sealed class SecretFieldDialog:Dlg,ILockableDialog {
        readonly TextBox name=new TextBox{Width=430,MaxLength=128};readonly TextBox value=new TextBox{Multiline=true,ScrollBars=ScrollBars.Vertical,Width=430,Height=160,MaxLength=65536};
        internal string FieldName{get{return name.Text.Trim();}}internal string Value{get{return value.Text;}}
        internal SecretFieldDialog(AccountSecretField field,bool viewOnly,IEnumerable<AccountSecretField> fields):base(viewOnly?"Просмотр защищённого поля":"Защищённое поле"){
            Note("На этом экране значение видно. Окно закроется при блокировке базы.");Row("Название:",name);Row("Значение:",value);Buttons();
            name.Text=field==null?"":field.Name;value.Text=field==null?"":field.Value;name.ReadOnly=value.ReadOnly=viewOnly;
            if(viewOnly){Ok.Text="Закрыть";Cancel.Visible=false;}else Ok.Click+=(s,e)=>{try{KdbxStore.ValidateFieldName(FieldName);if(fields.Any(f=>f!=field&&string.Equals(f.Name,FieldName,StringComparison.OrdinalIgnoreCase)))throw new InvalidOperationException("Поле с таким названием уже есть.");}catch(Exception ex){Fail(ex.Message);}};
        }
    }
    sealed class RecordPreviewDialog:Dlg,ILockableDialog {
        internal RecordPreviewDialog(LoginEntry entry,OtpEntry otp):base("Предыдущая версия — просмотр"){
            Note("Это сохранённая версия. Просмотр ничего не меняет; восстановление выполняется отдельной кнопкой.");
            var name=new TextBox{ReadOnly=true,Width=440,Text=otp!=null?otp.Title:entry.Name};Row("Название:",name);
            if(entry!=null){Row("Логин:",new TextBox{ReadOnly=true,Width=440,Text=entry.Login});Row("Адрес:",new TextBox{ReadOnly=true,Width=440,Text=entry.Target});}
            if(entry==null||entry.Kind!="passkey"){
                var secret=new TextBox{ReadOnly=true,Width=440,UseSystemPasswordChar=true};Row(otp==null?"Пароль:":"Ключ 2FA:",secret);secret.Text=otp==null?entry.Password:otp.Secret;
                var show=new CheckBox{Text="Показать секрет",AutoSize=true};show.CheckedChanged+=(s,e)=>secret.UseSystemPasswordChar=!show.Checked;Row("",show);
                var copy=new Button{Text="Скопировать секрет",AutoSize=true};copy.Click+=(s,e)=>SecureClip.Copy(secret.Text);Row("",copy);
            }else Note("Закрытый ключ passkey не показывается. Восстановление возвращает сохранённую версию ключа.");
            Row("Заметки:",new TextBox{ReadOnly=true,Multiline=true,Width=440,Height=75,Text=otp==null?entry.Notes:otp.Notes});
            if(entry!=null&&entry.CustomFields.Count>0){var fields=new Button{Text="Дополнительные поля…",AutoSize=true};fields.Click+=(s,e)=>{using(var dialog=new SecretFieldsDialog(entry.CustomFields,true))dialog.ShowDialog(this);};Row("",fields);}
            Buttons();Ok.Text="Закрыть";Cancel.Visible=false;
        }
    }
    sealed class RecordArchiveDialog:Form,ILockableDialog {
        readonly KdbxStore store;readonly string id;readonly bool otp;readonly Func<bool> save;
        readonly ListView history=List(),trash=List();readonly Label status=new Label{Dock=DockStyle.Bottom,Height=48,Padding=new Padding(6)};
        static ListView List(){var list=new ListView{View=View.Details,FullRowSelect=true,Dock=DockStyle.Fill};list.Columns.Add("Время",170);list.Columns.Add("Название",300);list.Columns.Add("Тип",90);return list;}
        internal RecordArchiveDialog(KdbxStore store,string id,bool otp,Func<bool> save):base(){
            this.store=store;this.id=id;this.otp=otp;this.save=save;Text="История и корзина записей";Icon=AppIcons.Open;Font=new Font("Segoe UI",9f);Size=new Size(690,480);MinimumSize=new Size(570,350);StartPosition=FormStartPosition.CenterParent;
            var tabs=new TabControl{Dock=DockStyle.Fill};Controls.Add(tabs);Controls.Add(status);TabPage historyPage=new TabPage("История выбранной записи"),trashPage=new TabPage("Корзина");tabs.TabPages.AddRange(new[]{historyPage,trashPage});
            historyPage.Controls.Add(history);trashPage.Controls.Add(trash);FlowLayoutPanel hbar=new FlowLayoutPanel{Dock=DockStyle.Top,AutoSize=true},tbar=new FlowLayoutPanel{Dock=DockStyle.Top,AutoSize=true};historyPage.Controls.Add(hbar);trashPage.Controls.Add(tbar);
            Button(hbar,"Посмотреть версию…",Preview);Button(hbar,"Восстановить версию",RestoreVersion);Button(tbar,"Восстановить выбранное",RestoreTrash);Button(tbar,"Удалить окончательно",Purge);
            var bottom=new FlowLayoutPanel{Dock=DockStyle.Bottom,AutoSize=true};Controls.Add(bottom);Button(bottom,"Закрыть",Close);RefreshRows();if(id==null)tabs.SelectedTab=trashPage;
        }
        protected override void OnHandleCreated(EventArgs e){base.OnHandleCreated(e);Win.ApplyCaptureProtection(this);}
        protected override void OnLoad(EventArgs e){Appearance.Apply(this);base.OnLoad(e);}
        void Button(FlowLayoutPanel bar,string text,Action action){var button=new Button{Text=text,AutoSize=true};button.Click+=(s,e)=>{try{action();}catch(Exception ex){MessageBox.Show(this,ex.Message,Text);}};bar.Controls.Add(button);}
        void RefreshRows(){history.Items.Clear();trash.Items.Clear();if(id!=null)foreach(var row in store.Versions(id,otp))Add(history,row);foreach(var row in store.DeletedRecords())Add(trash,row);status.Text=history.Items.Count+" предыдущих версий. В корзине: "+trash.Items.Count+". Старые резервные копии сохраняют данные, удалённые из текущей базы.";}
        static void Add(ListView list,RecordVersion row){list.Items.Add(new ListViewItem(new[]{row.Time.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss"),row.Name,row.Kind=="otp"?"2FA":row.Kind=="passkey"?"Passkey":"Пароль"}){Tag=row});}
        RecordVersion Selected(ListView list){return list.SelectedItems.Count==0?null:(RecordVersion)list.SelectedItems[0].Tag;}
        void Preview(){var row=Selected(history);if(row==null)return;LoginEntry entry=null;OtpEntry code=null;try{if(otp)code=store.HistoryOtp(id,row.Index);else entry=store.HistoryEntry(id,row.Index);using(var dialog=new RecordPreviewDialog(entry,code))dialog.ShowDialog(this);}finally{if(entry!=null)entry.ClearSecrets();if(code!=null)code.ClearSecret();}}
        void RestoreVersion(){var row=Selected(history);if(row==null)return;if(MessageBox.Show(this,"Вернуть выбранную версию? Текущее состояние останется в истории.",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes||IsDisposed)return;store.RestoreHistory(id,row.Index,otp);if(save())RefreshRows();else Close();}
        void RestoreTrash(){var row=Selected(trash);if(row==null)return;int restored=store.RestoreDeleted(row.Id);if(save()){RefreshRows();status.Text="Восстановлено записей: "+restored+". Доступные связанные 2FA/ключи также возвращены.";}else Close();}
        void Purge(){var row=Selected(trash);if(row==null)return;if(MessageBox.Show(this,"Удалить запись и её историю из текущей базы окончательно? Старые резервные копии останутся.",Text,MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes||IsDisposed)return;store.PurgeDeleted(new[]{row.Id});if(save())RefreshRows();else Close();}
    }
    partial class MainForm {
        void ShowRecordArchive(string id,bool otp=false){if(vault==null)return;var current=vault;using(var dialog=new RecordArchiveDialog(current,id,otp,()=>{if(vault!=current)return false;bool result=SaveVault();RefreshOtp();RefreshPasskeys();return result;}))dialog.ShowDialog(this);}
        void EditSelectedFields(){var entry=SelectedEntry();if(vault==null||entry==null)return;var current=vault;var copy=entry.Copy();bool kept=false;try{using(var dialog=new SecretFieldsDialog(copy.CustomFields)){if(dialog.ShowDialog(this)!=DialogResult.OK||vault!=current)return;int index=current.Entries.IndexOf(entry);if(index<0)return;current.Entries[index]=copy;if(SaveVault()){kept=true;entry.ClearSecrets();}else if(vault==current&&index<current.Entries.Count&&current.Entries[index]==copy)current.Entries[index]=entry;else entry.ClearSecrets();}}finally{if(!kept)copy.ClearSecrets();}}
    }
}

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace WinUp {
    class AdvancedRecordForm:Form,ILockableDialog {
        protected readonly FlowLayoutPanel Bar=new FlowLayoutPanel{Dock=DockStyle.Top,AutoSize=true};
        protected readonly Label Status=new Label{Dock=DockStyle.Bottom,Height=55,Padding=new Padding(6)};
        protected readonly KdbxStore Store;protected readonly Func<bool> Save;
        protected AdvancedRecordForm(string title,KdbxStore store,Func<bool> save){Store=store;Save=save;Text=title;Font=new Font("Segoe UI",9);Icon=AppIcons.Open;Size=new Size(740,510);MinimumSize=new Size(580,360);StartPosition=FormStartPosition.CenterParent;Controls.Add(Bar);Controls.Add(Status);}
        protected override void OnHandleCreated(EventArgs e){base.OnHandleCreated(e);Win.ApplyCaptureProtection(this);}
        protected override void OnLoad(EventArgs e){Appearance.Apply(this);base.OnLoad(e);}
        protected void Button(string caption,Action action){var b=new Button{Text=caption,AutoSize=true};b.Click+=(s,e)=>{try{if(!IsDisposed)action();}catch(Exception ex){if(!IsDisposed)MessageBox.Show(this,ex.Message,Text);}};Bar.Controls.Add(b);}
        protected bool Persist(){if(Save())return true;Close();return false;}
    }
    sealed class GroupEditDialog:Dlg,ILockableDialog {
        readonly TextBox name=new TextBox();readonly ComboBox parent=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList};
        internal string GroupName{get{return name.Text.Trim();}}internal string ParentId{get{return ((AccountGroupInfo)parent.SelectedItem).Id;}}
        internal GroupEditDialog(IEnumerable<AccountGroupInfo> groups,AccountGroupInfo current,string parentId):base(current==null?"Новая группа":"Изменить группу"){
            Row("Название:",name);Row("Родительская группа:",parent);foreach(var g in groups.Where(g=>current==null||g.Id!=current.Id))parent.Items.Add(g);parent.SelectedItem=parent.Items.Cast<AccountGroupInfo>().FirstOrDefault(g=>g.Id==parentId);if(parent.SelectedIndex<0&&parent.Items.Count>0)parent.SelectedIndex=0;name.Text=current==null?"":current.Name;Buttons();Ok.Click+=(s,e)=>{if(string.IsNullOrWhiteSpace(name.Text)||parent.SelectedItem==null)Fail("Введите название и выберите родительскую группу.");};
        }
    }
    sealed class AccountGroupsDialog:AdvancedRecordForm {
        readonly TreeView tree=new TreeView{Dock=DockStyle.Fill,HideSelection=false};
        internal AccountGroupsDialog(KdbxStore store,Func<bool> save):base("Группы аккаунтов",store,save){Controls.Add(tree);tree.BringToFront();Button("Добавить…",()=>Edit(false));Button("Изменить / переместить…",()=>Edit(true));Button("Удалить пустую группу",Delete);Button("Закрыть",Close);RefreshTree();Status.Text="Изменения сохраняются сразу. Для переноса аккаунта выберите группу в окне «Изменить». Фильтр группы включает её вложенные группы.";}
        AccountGroupInfo Selected{get{return tree.SelectedNode==null?null:tree.SelectedNode.Tag as AccountGroupInfo;}}
        void RefreshTree(string id=null){tree.Nodes.Clear();var nodes=new Dictionary<string,TreeNode>();foreach(var g in Store.AccountGroups()){var node=new TreeNode(g.ParentId==null?"Все аккаунты":g.Name){Tag=g};nodes.Add(g.Id,node);TreeNode parent;if(g.ParentId!=null&&nodes.TryGetValue(g.ParentId,out parent))parent.Nodes.Add(node);else tree.Nodes.Add(node);if(g.Id==id)tree.SelectedNode=node;}tree.ExpandAll();if(tree.SelectedNode==null&&tree.Nodes.Count>0)tree.SelectedNode=tree.Nodes[0];}
        void Edit(bool existing){var selected=Selected;if(selected==null)return;if(existing&&selected.ParentId==null)return;using(var d=new GroupEditDialog(Store.AccountGroups(),existing?selected:null,existing?selected.ParentId:selected.Id)){if(d.ShowDialog(this)!=DialogResult.OK||IsDisposed)return;string id=existing?selected.Id:Store.CreateAccountGroup(d.ParentId,d.GroupName);if(existing)Store.ChangeAccountGroup(id,d.ParentId,d.GroupName);if(Persist())RefreshTree(id);}}
        void Delete(){var g=Selected;if(g==null||g.ParentId==null)return;Store.DeleteAccountGroup(g.Id);if(Persist())RefreshTree();}
    }
    sealed class AttachmentsDialog:AdvancedRecordForm {
        readonly string id;readonly ListView list=new ListView{View=View.Details,Dock=DockStyle.Fill,FullRowSelect=true,MultiSelect=false,HideSelection=false};
        internal AttachmentsDialog(KdbxStore store,string id,Func<bool> save):base("Вложения к аккаунту",store,save){this.id=id;list.Columns.Add("Файл",430);list.Columns.Add("Размер",110);Controls.Add(list);list.BringToFront();Button("Добавить файл…",Add);Button("Сохранить файл как…",Export);Button("Удалить вложение",Delete);Button("Закрыть",Close);RefreshList();Status.Text="Файлы хранятся внутри зашифрованной записи: до 2 МБ каждый, до 16 МБ на аккаунт. При сохранении на диск файл будет расшифрован. Удалённое вложение остаётся в истории записи.";}
        AccountAttachmentInfo Selected{get{return list.SelectedItems.Count==0?null:list.SelectedItems[0].Tag as AccountAttachmentInfo;}}
        void RefreshList(){list.Items.Clear();foreach(var f in Store.Attachments(id))list.Items.Add(new ListViewItem(new[]{f.Name,f.Size<1024?f.Size.ToString()+" Б":(f.Size/1024.0).ToString("0.#")+" КБ"}){Tag=f});}
        void Add(){using(var d=new OpenFileDialog{Title="Прикрепить небольшой файл",CheckFileExists=true}){if(d.ShowDialog(this)!=DialogResult.OK||IsDisposed)return;Store.AddAttachment(id,d.FileName);if(Persist())RefreshList();}}
        void Export(){var f=Selected;if(f==null)return;using(var d=new SaveFileDialog{Title="Сохранить расшифрованный файл",FileName=f.Name,OverwritePrompt=true}){if(d.ShowDialog(this)!=DialogResult.OK||IsDisposed)return;Store.ExportAttachment(id,f.Name,d.FileName);Status.Text="Файл сохранён в расшифрованном виде: "+d.FileName;}}
        void Delete(){var f=Selected;if(f==null)return;if(MessageBox.Show(this,"Удалить вложение «"+f.Name+"»? Предыдущая версия останется в истории записи.",Text,MessageBoxButtons.YesNo)!=DialogResult.Yes||IsDisposed)return;Store.RemoveAttachment(id,f.Name);if(Persist())RefreshList();}
    }
    sealed class FieldReferenceDialog:Dlg,ILockableDialog {
        sealed class Item{internal LoginEntry Entry;public override string ToString(){return Entry.Name+" — "+Entry.Login;}}
        readonly ComboBox source=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList};
        readonly CheckBox login=new CheckBox{Text="Использовать логин выбранной записи",AutoSize=true},password=new CheckBox{Text="Использовать пароль выбранной записи",AutoSize=true,Checked=true};
        internal LoginEntry Source{get{return ((Item)source.SelectedItem).Entry;}}internal bool LinkLogin{get{return login.Checked;}}internal bool LinkPassword{get{return password.Checked;}}
        internal FieldReferenceDialog(LoginEntry entry,IEnumerable<LoginEntry> entries):base("Ссылки между полями"){
            Note("Выберите основной аккаунт. Его логин или пароль будет использоваться при копировании и входе. После смены пароля в основном аккаунте связанные записи получат новый пароль автоматически.");
            foreach(var e in entries.Where(e=>e.Id!=entry.Id&&e.Kind!="passkey").OrderBy(e=>e.Name))source.Items.Add(new Item{Entry=e});if(source.Items.Count>0)source.SelectedIndex=0;Row("Основной аккаунт:",source);Row("",login);Row("",password);Note("Ссылка хранится в формате KeePass. Удаление основного аккаунта прервёт вход: сначала замените ссылку или восстановите запись из корзины.");Buttons();Ok.Click+=(s,e)=>{if(source.SelectedItem==null||(!login.Checked&&!password.Checked))Fail("Выберите запись и хотя бы одно поле.");};
        }
    }
    sealed class MergePasswordDialog:Dlg,ILockableDialog {
        readonly TextBox password=new TextBox{UseSystemPasswordChar=true},key=new TextBox();internal string Password{get{return password.Text;}}internal string KeyFile{get{return key.Text.Trim();}}
        internal MergePasswordDialog():base("Открыть вторую копию базы"){Row("Пароль второй копии:",password);var pick=new Button{Text="Обзор…",AutoSize=true};Row("Ключ-файл, если нужен:",WithButton(key,pick));pick.Click+=(s,e)=>{using(var d=new OpenFileDialog{CheckFileExists=true})if(d.ShowDialog(this)==DialogResult.OK&&!IsDisposed)key.Text=d.FileName;};Note("Вторая копия не изменяется. Результат сохранится в открытой базе WinUp. Перед объединением будет создана зашифрованная резервная копия.");Buttons();}
    }
    sealed class MergePreviewDialog:Form,ILockableDialog {
        readonly DataGridView grid=new DataGridView{Dock=DockStyle.Fill,AutoGenerateColumns=false,AllowUserToAddRows=false,AllowUserToDeleteRows=false,RowHeadersVisible=false};readonly DatabaseMerge merge;
        internal MergePreviewDialog(DatabaseMerge merge){this.merge=merge;Text="Объединение копий базы";Size=new Size(850,520);MinimumSize=new Size(640,400);StartPosition=FormStartPosition.CenterParent;Font=new Font("Segoe UI",9);Icon=AppIcons.Open;
            var info=new Label{Dock=DockStyle.Top,Height=95,Padding=new Padding(8),Text="Новых записей: "+merge.Added+". Различающихся записей: "+merge.Conflicts.Count+". Окончательных удалений: "+merge.Removed+".\nВыберите версию каждой различающейся записи. Предыдущие версии существующих записей остаются в истории. Окончательное удаление можно отменить из резерва до объединения. Группы, метки, вложения и корзина также объединяются."};
            grid.Columns.Add(new DataGridViewTextBoxColumn{Name="Name",HeaderText="Запись",ReadOnly=true,Width=240});grid.Columns.Add(new DataGridViewTextBoxColumn{Name="Local",HeaderText="Эта база",ReadOnly=true,Width=160});grid.Columns.Add(new DataGridViewTextBoxColumn{Name="Remote",HeaderText="Вторая копия",ReadOnly=true,Width=160});var choice=new DataGridViewComboBoxColumn{Name="Choice",HeaderText="Оставить",Width=160};choice.Items.AddRange("Более новая","Эта база","Вторая копия");grid.Columns.Add(choice);foreach(var c in merge.Conflicts)grid.Rows.Add(c.Name,(c.LocalDeleted?"Удалена ":"")+c.LocalTime.ToLocalTime().ToString("g"),(c.OtherDeleted?"Удалена ":"")+c.OtherTime.ToLocalTime().ToString("g"),c.Choice);
            var bar=new FlowLayoutPanel{Dock=DockStyle.Bottom,AutoSize=true,FlowDirection=FlowDirection.RightToLeft};var cancel=new Button{Text="Отмена",DialogResult=DialogResult.Cancel,AutoSize=true};var ok=new Button{Text="Объединить",AutoSize=true};bar.Controls.Add(cancel);bar.Controls.Add(ok);Controls.Add(grid);Controls.Add(info);Controls.Add(bar);CancelButton=cancel;ok.Click+=(s,e)=>{grid.EndEdit();for(int i=0;i<merge.Conflicts.Count;i++)merge.Conflicts[i].Choice=(string)grid.Rows[i].Cells[3].Value;DialogResult=DialogResult.OK;};}
        protected override void OnHandleCreated(EventArgs e){base.OnHandleCreated(e);Win.ApplyCaptureProtection(this);}
        protected override void OnLoad(EventArgs e){Appearance.Apply(this);base.OnLoad(e);}
    }
    partial class MainForm {
        Func<bool> AdvancedSave(KdbxStore current){return ()=>{if(vault!=current)return false;bool result=SaveVault();RefreshOtp();RefreshPasskeys();return result;};}
        void ManageAccountGroups(){if(vault==null)return;var current=vault;using(var d=new AccountGroupsDialog(current,AdvancedSave(current)))d.ShowDialog(this);if(vault==current)RefreshEntries();}
        void ManageAttachments(){var entry=SelectedEntry();if(vault==null||entry==null)return;var current=vault;using(var d=new AttachmentsDialog(current,entry.Id,AdvancedSave(current)))d.ShowDialog(this);}
        void ManageReferences(){var entry=SelectedEntry();if(vault==null||entry==null)return;var current=vault;using(var d=new FieldReferenceDialog(entry,current.Entries)){if(d.ShowDialog(this)!=DialogResult.OK||vault!=current)return;var copy=entry.Copy();bool kept=false;try{if(d.LinkLogin)copy.Login=KdbxStore.Reference(d.Source.Id,'U');if(d.LinkPassword)copy.Password=KdbxStore.Reference(d.Source.Id,'P');current.ValidateReferenceChange(copy);int index=current.Entries.IndexOf(entry);if(index<0)return;current.Entries[index]=copy;if(SaveVault()){kept=true;entry.ClearSecrets();}else if(vault==current&&index<current.Entries.Count)current.Entries[index]=entry;else entry.ClearSecrets();}finally{if(!kept)copy.ClearSecrets();}}}
        void MergeDatabaseCopies(){if(vault==null)return;var current=vault;try{string path;using(var d=new OpenFileDialog{Title="Копия базы с другого устройства",Filter="База KeePass (*.kdbx)|*.kdbx",CheckFileExists=true}){if(d.ShowDialog(this)!=DialogResult.OK||vault!=current)return;path=d.FileName;}using(var d=new MergePasswordDialog()){if(d.ShowDialog(this)!=DialogResult.OK||vault!=current)return;byte[] key=string.IsNullOrEmpty(d.KeyFile)?null:SafeStorage.ReadBounded(d.KeyFile,1024*1024);try{using(var merge=current.PreviewMerge(path,d.Password,key))using(var preview=new MergePreviewDialog(merge)){if(preview.ShowDialog(this)!=DialogResult.OK||vault!=current)return;string backup=Path.Combine(Paths.Data,"before-merge-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,8)+".kdbx");current.SaveBeforeMerge(backup);current.ApplyMerge(merge);if(AdvancedSave(current)())MessageBox.Show(this,"Копии объединены. Резервная копия до объединения:\n"+backup,"WinUp");}}finally{if(key!=null)Array.Clear(key,0,key.Length);}}}catch(Exception ex){MessageBox.Show(this,ex.Message,"WinUp — объединение баз");}}
    }
}

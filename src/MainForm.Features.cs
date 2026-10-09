using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp {
    partial class MainForm {
        FileVaultClient fileVault;
        readonly ComboBox fileCatalog=new ComboBox { DropDownStyle=ComboBoxStyle.DropDownList, Width=310 };
        readonly ListView fileItems=new ListView { Dock=DockStyle.Fill, View=View.Details, FullRowSelect=true };
        readonly Label fileState=new Label { AutoSize=true, Text="Хранилище закрыто", Padding=new Padding(8) };
        readonly ListView passkeyList=new ListView { Dock=DockStyle.Fill, View=View.Details, FullRowSelect=true };
        string fileDirectory="";
        int fileGeneration;
        bool fileBusy;
        bool fileLockRequested;
        System.Threading.CancellationTokenSource fileCancellation;
        FileVaultPreferences filePreferences=new FileVaultPreferences();
        DateTime fileHistoryAt=DateTime.MinValue;
        bool fileCatalogReset;
        static Button FeatureButton(string title,Action action) {
            var b=new Button { Text=title, AutoSize=true, Margin=new Padding(4) };
            b.Click+=(s,e)=> { try { action(); } catch(Exception ex) { MessageBox.Show(b.FindForm(),ex.Message,"WinUp",MessageBoxButtons.OK,MessageBoxIcon.Warning); } }; return b;
        }
        void SelectTab(string title) { var page=tabs.TabPages.Cast<TabPage>().FirstOrDefault(x=>x.Text==title); if(page!=null) tabs.SelectedTab=page; }
        bool NeedVault() { if(vault==null) Unlock(); return vault!=null; }
        bool EnsureFileVault() {
            if(fileBusy) { fileState.Text="Дождитесь завершения текущей операции или отмените её."; return false; }
            if(fileVault!=null && fileVault.Open) return true;
            using(var choice=new FileVaultChoiceDialog(fileCatalog.SelectedItem as string)) {
                var result=choice.ShowDialog(this);
                if(result==DialogResult.Yes) CreateFileVault();
                else if(result==DialogResult.No) { if(fileCatalog.SelectedItem==null) AttachFileVault(); if(fileCatalog.SelectedItem!=null) OpenFileVault(); }
            }
            return fileVault!=null && fileVault.Open;
        }
        void EncryptExistingFile() {
            if(fileBusy) return;
            using(var picker=new OpenFileDialog {Title="Выберите существующий файл для шифрования",Multiselect=true})
                if(picker.ShowDialog(this)==DialogResult.OK && EnsureFileVault()) ImportPaths(picker.FileNames);
        }
        void BuildFileVaultTab() {
            var page=new TabPage("Файлы");
            var bar=new FlowLayoutPanel { Dock=DockStyle.Top,AutoSize=true,WrapContents=true };
            fileItems.Columns.Add("Название",420); fileItems.Columns.Add("Размер",110); fileItems.Columns.Add("Тип",100);
            bar.Controls.Add(fileCatalog);
            bar.Controls.Add(FeatureButton("Создать хранилище",CreateFileVault));
            bar.Controls.Add(FeatureButton("Добавить существующее",AttachFileVault));
            bar.Controls.Add(FeatureButton("Открыть",OpenFileVault));
            bar.Controls.Add(FeatureButton("Заблокировать хранилище",CloseFileVaultSafely));
            bar.Controls.Add(FeatureButton("В Проводнике",MountFileVault));
            bar.Controls.Add(FeatureButton("Зашифровать файлы…",delegate{PackExternal(false);}));
            bar.Controls.Add(FeatureButton("Зашифровать папку…",delegate{PackExternal(true);}));
            bar.Controls.Add(FeatureButton("Расшифровать пакет…",UnpackFilePackage));
            bar.Controls.Add(FeatureButton("Без WinUp…",ShowFileInteroperability));
            bar.Controls.Add(FeatureButton("Добавить файлы",delegate { ImportFiles(false); }));
            bar.Controls.Add(FeatureButton("Добавить папку",delegate { ImportFiles(true); }));
            bar.Controls.Add(FeatureButton("Выгрузить…",ExportFileSelection));
            bar.Controls.Add(FeatureButton("История файлов…",ShowFileHistory));
            bar.Controls.Add(FeatureButton("Резерв / перенос…",BackupFileVault));
            var more=FeatureButton("Ещё…",delegate{});var menu=new ContextMenuStrip();
            AddFileMenu(menu,"Снять версию сейчас",SaveFileCheckpoint);
            AddFileMenu(menu,"Удалить выбранное",DeleteFileSelection);
            AddFileMenu(menu,"Проверить резерв",VerifyFileBackup);
            AddFileMenu(menu,"Проверить пакет",VerifyFilePackage);
            AddFileMenu(menu,"Настройки хранилища / проекта",ConfigureFileVault);
            AddFileMenu(menu,"Скопировать путь проекта",CopyProjectPath);
            AddFileMenu(menu,"Открыть проект в редакторе",OpenProjectEditor);
            AddFileMenu(menu,"Обновить список",RefreshFileItems);
            more.Click+=(s,e)=>menu.Show(more,new Point(0,more.Height));bar.Controls.Add(more);
            bar.Controls.Add(FeatureButton("Новая папка",MakeFileDirectory));
            bar.Controls.Add(FeatureButton("Назад",delegate { int i=fileDirectory.LastIndexOf('/'); fileDirectory=i<0 ? "" : fileDirectory.Substring(0,i); RefreshFileItems(); }));
            bar.Controls.Add(FeatureButton("Отмена операции",delegate { if(fileCancellation!=null)fileCancellation.Cancel(); }));
            fileItems.DoubleClick+=(s,e)=>OpenFileItem();
            fileItems.AllowDrop=true;
            fileItems.DragEnter+=(s,e)=> { if(!fileBusy && fileVault!=null && e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect=DragDropEffects.Copy; };
            fileItems.DragDrop+=(s,e)=> { if(!fileBusy && fileVault!=null) ImportPaths((string[])e.Data.GetData(DataFormats.FileDrop)); };
            fileCatalog.SelectedIndexChanged+=(s,e)=> {
                if(!fileCatalogReset&&fileVault!=null) {
                    string previous=fileVault.Folder;
                    if(!TryCloseFileVault()) {fileCatalogReset=true;try{fileCatalog.SelectedItem=previous;}finally{fileCatalogReset=false;}}
                }
            };
            FormClosing+=(s,e)=>{if(fileBusy){e.Cancel=true;fileState.Text="Сначала завершите или отмените операцию с файлами.";}else if(fileVault!=null&&!TryCloseFileVault())e.Cancel=true;};
            page.Controls.Add(fileItems); page.Controls.Add(fileState); fileState.Dock=DockStyle.Bottom;
            page.Controls.Add(bar);
            ArrangeActions(page,new[]{bar},
                new ActionGroup("Хранилище",new[]{(Control)fileCatalog}.Concat(Actions(bar,"Открыть","В Проводнике","Заблокировать хранилище")).ToArray()),
                new ActionGroup("Файлы",Actions(bar,"Назад","Новая папка","Добавить файлы","Добавить папку","Выгрузить…")),
                new ActionGroup("Пакеты",Actions(bar,"Зашифровать файлы…","Зашифровать папку…","Расшифровать пакет…","Без WinUp…")),
                new ActionGroup("Управление",Actions(bar,"Создать хранилище","Добавить существующее","История файлов…","Резерв / перенос…","Ещё…","Отмена операции")));
            tabs.TabPages.Add(page);
            try {
                string path=Path.Combine(Paths.Data,"file-vaults.json");
                if(File.Exists(path)) foreach(string folder in new JavaScriptSerializer().Deserialize<string[]>(File.ReadAllText(path)))
                    if(Path.IsPathRooted(folder) && !fileCatalog.Items.Contains(folder)) fileCatalog.Items.Add(folder);
            } catch { }
            if(fileCatalog.Items.Count>0) fileCatalog.SelectedIndex=0;
        }
        void RememberFileVault(string folder) {
            if(!fileCatalog.Items.Contains(folder)) fileCatalog.Items.Add(folder);
            fileCatalog.SelectedItem=folder;
            string path=Path.Combine(Paths.Data,"file-vaults.json"), temp=path+".tmp";
            try {
                File.WriteAllText(temp,new JavaScriptSerializer().Serialize(fileCatalog.Items.Cast<string>().ToArray()));
                if(File.Exists(path)) File.Replace(temp,path,null); else File.Move(temp,path);
            } catch(Exception ex) { MessageBox.Show(this,"Хранилище сохранено, но список папок не обновлён: "+ex.Message,"WinUp"); }
        }
        void AttachFileVault() {
            if(fileBusy) return;
            using(var d=new FolderBrowserDialog { Description="Выберите папку зашифрованного хранилища",ShowNewFolderButton=false }) {
                if(d.ShowDialog(this)!=DialogResult.OK) return;
                if(!File.Exists(Path.Combine(d.SelectedPath,"vault.cryptomator")) || !File.Exists(Path.Combine(d.SelectedPath,"masterkey.cryptomator"))) {
                    MessageBox.Show(this,"В этой папке нет поддерживаемого файлового хранилища.","WinUp"); return;
                }
                RememberFileVault(d.SelectedPath);
            }
        }
        void CreateFileVault() {
            if(fileBusy) return;
            if(!TryCloseFileVault())return;
            using(var d=new FileVaultDialog(true)) {
                if(d.ShowDialog(this)!=DialogResult.OK) return;
                int gen=fileGeneration; string pw=d.Password;
                try {
                    FileVaultClient created=null;
                    string folder=d.Folder;
                    FileOperation(delegate { Directory.CreateDirectory(Path.GetDirectoryName(folder)); created=new FileVaultClient(folder,pw,true,fileCancellation.Token); });
                    if(created==null) return;
                    if(gen!=fileGeneration) { created.Dispose(); return; }
                    RememberFileVault(created.Folder); fileVault=created;filePreferences=FileVaultPreferences.Load(created.Folder); fileDirectory=""; RefreshFileItems();
                } finally { Secure.Wipe(pw); }
            }
        }
        void OpenFileVault() {
            if(fileBusy) return;
            if(fileCatalog.SelectedItem==null) AttachFileVault();
            if(fileCatalog.SelectedItem==null) return;
            string folder=(string)fileCatalog.SelectedItem;
            if(!TryCloseFileVault())return;
            filePreferences=FileVaultPreferences.Load(folder);
            using(var d=new FileVaultDialog(false,folder)) {
                if(d.ShowDialog(this)!=DialogResult.OK) return;
                int gen=fileGeneration; string pw=d.Password;
                try {
                    FileVaultClient opened=null;
                    FileOperation(delegate {
                        if(filePreferences.AutoBackup && !filePreferences.ReadOnly)AutoBackupBeforeOpen(folder,fileCancellation.Token);
                        opened=new FileVaultClient(folder,pw,false,fileCancellation.Token,filePreferences.ReadOnly);
                    },false);
                    if(opened==null) return;
                    if(gen!=fileGeneration) { opened.Dispose(); return; }
                    fileVault=opened; fileDirectory=""; RefreshFileItems();
                } finally { Secure.Wipe(pw); }
            }
        }
        void CloseFileVault() {
            fileGeneration++;
            if(fileCancellation!=null) fileCancellation.Cancel();
            var old=fileVault; fileVault=null;
            fileItems.Items.Clear(); fileDirectory=""; fileState.Text="Хранилище закрыто";
            if(old!=null) { old.Cancel(); System.Threading.Tasks.Task.Run((Action)old.Dispose); }
            UpdateLockUi();
        }
        void CloseFileVaultSafely() {
            CloseFileSecretDialogs();
            if(fileBusy || fileVault==null) return;
            TryCloseFileVault();
        }
        void CloseFileSecretDialogs(){foreach(Form dialog in Application.OpenForms.Cast<Form>().ToArray())if(dialog!=this&&dialog is IFileSecretDialog)try{dialog.DialogResult=DialogResult.Cancel;dialog.Close();}catch{}}
        bool FileOperation(Action action,bool cancelVault=true) {
            if(fileBusy) return false;
            fileBusy=true; fileState.Text="Выполняю операцию…";
            fileCancellation=new System.Threading.CancellationTokenSource();
            try {
                var task=System.Threading.Tasks.Task.Run(action);
                using(var progress=new FileProgressDialog(task,delegate { fileCancellation.Cancel(); if(cancelVault&&fileVault!=null) fileVault.Cancel(); }))
                    progress.ShowDialog(this);
                task.GetAwaiter().GetResult();
                return true;
            }
            catch(Exception ex) { MessageBox.Show(this,ex is OperationCanceledException ? "Операция отменена. Уже завершённые действия сохраняются. Проверьте выбранные файлы и результат." : ex.Message,"WinUp — файлы",MessageBoxButtons.OK,MessageBoxIcon.Warning);return false; }
            finally { fileCancellation.Dispose(); fileCancellation=null; fileBusy=false; fileState.Text=fileVault!=null && fileVault.Open ? "Открыто: /"+fileDirectory+(fileVault.MountPoint==null ? "" : " · "+fileVault.MountPoint) : "Хранилище закрыто";
                if(fileLockRequested){fileLockRequested=false;if(!IsDisposed&&IsHandleCreated)BeginInvoke((Action)CloseFileVaultSafely);}
            }
        }
        void RefreshFileItems() {
            var client=fileVault; if(client==null || fileBusy) return;
            Dictionary<string,object> result=null;
            FileOperation(delegate { result=client.Call("list",fileDirectory); });
            if(result==null || client!=fileVault) return;
            fileItems.Items.Clear();
            foreach(Dictionary<string,object> item in (ArrayList)result["items"]) {
                bool directory=(bool)item["directory"];
                var row=new ListViewItem(new[] { (string)item["name"],directory ? "" : Convert.ToInt64(item["size"]).ToString("N0")+" Б",directory ? "папка" : "файл" }) { Tag=directory };
                fileItems.Items.Add(row);
            }
            fileState.Text="Открыто: /"+fileDirectory+(client.MountPoint==null ? "" : " · "+client.MountPoint);
            if(client.ReadOnly)fileState.Text+=" · только чтение";
            UpdateLockUi();
        }
        void MakeFileDirectory() {
            if(!EnsureFileVault()) return;
            if(!BeforeFileChange())return;
            using(var d=new FeatureNameDialog("Новая папка","Название папки:")) {
                if(d.ShowDialog(this)!=DialogResult.OK) return;
                var client=fileVault; FileOperation(delegate { client.Call("mkdir",FileNameInVault(d.Value)); }); RefreshFileItems();
            }
        }
        string FileNameInVault(string name) { return fileDirectory.Length==0 ? name : fileDirectory+"/"+name; }
        void ImportFiles(bool folder) {
            if(!EnsureFileVault()) return;
            if(folder) using(var d=new FolderBrowserDialog { Description="Папка для шифрования" }) {
                if(d.ShowDialog(this)==DialogResult.OK) ImportPaths(new[] { d.SelectedPath });
            } else using(var d=new OpenFileDialog { Multiselect=true,Title="Файлы для шифрования" }) {
                if(d.ShowDialog(this)==DialogResult.OK) ImportPaths(d.FileNames);
            }
        }
        void ImportPaths(string[] sources) {
            if(fileVault==null || fileBusy || sources==null || sources.Length==0) return;
            bool move;
            using(var mode=new FileImportModeDialog()) {if(mode.ShowDialog(this)!=DialogResult.OK)return;move=mode.MoveOriginals;}
            if(!BeforeFileChange())return;
            var client=fileVault; string directory=fileDirectory;
            FileOperation(delegate {
                foreach(string source in sources) {
                    if(client!=fileVault || !client.Open) throw new IOException("Операция отменена. Не перенесённые исходники сохранены.");
                    string name=Path.GetFileName(source.TrimEnd('\\'));
                    client.Import(source,directory.Length==0 ? name : directory+"/"+name,move);
                }
            });
            RefreshFileItems();
        }
        void OpenFileItem() {
            if(fileVault==null || fileBusy || fileItems.SelectedItems.Count==0) return;
            var item=fileItems.SelectedItems[0]; string path=FileNameInVault(item.Text);
            if((bool)item.Tag) { fileDirectory=path; RefreshFileItems(); return; }
            using(var d=new SaveFileDialog { FileName=item.Text,Title="Сохранить расшифрованную копию",OverwritePrompt=true }) {
                if(d.ShowDialog(this)!=DialogResult.OK) return;
                if(File.Exists(d.FileName)) { MessageBox.Show(this,"Выберите новое имя: существующие файлы не заменяются.","WinUp"); return; }
                var client=fileVault;
                FileOperation(delegate { SafePaths.NoReparseParents(d.FileName); client.Call("export",path,d.FileName); });
            }
        }
        void MountFileVault() {
            if(!EnsureFileVault()) return;
            if(!WinFspDriver.Installed) {
                if(MessageBox.Show(this,"Для диска в Проводнике нужен системный компонент WinFsp. Установить его?\nWindows запросит права администратора. Работа с файлами внутри WinUp доступна без него.","WinUp",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes) return;
                bool installed=false;
                FileOperation(delegate { installed=WinFspDriver.Install(); });
                if(!installed || fileVault==null) return;
            }
            if(fileVault.MountPoint!=null) { System.Diagnostics.Process.Start("explorer.exe",fileVault.MountPoint); return; }
            if(!fileVault.ReadOnly && !Checkpoint(false))return;
            string drive=filePreferences.Drive;
            if(drive!="" && Directory.Exists(drive)) { MessageBox.Show(this,"Выбранная буква "+drive+" занята. Освободите её или измените настройки хранилища.","WinUp"); return; }
            if(drive=="")drive=Enumerable.Range('D', 'Z'-'D'+1).Reverse().Select(c=>(char)c+":\\").FirstOrDefault(x=>!Directory.Exists(x));
            if(drive==null) { MessageBox.Show(this,"Нет свободной буквы диска.","WinUp"); return; }
            var client=fileVault; FileOperation(delegate { client.Mount(drive); });
            if(client==fileVault && client.MountPoint!=null) System.Diagnostics.Process.Start("explorer.exe",client.MountPoint);
        }
        void BuildPasskeyTab() {
            var page=new TabPage("Ключи доступа");
            passkeyList.Columns.Add("Сайт",300); passkeyList.Columns.Add("Аккаунт",300);
            var bar=new FlowLayoutPanel { Dock=DockStyle.Top,AutoSize=true };
            bar.Controls.Add(FeatureButton("Добавить ключ…",AddPasskeyFromSite));
            bar.Controls.Add(FeatureButton("Открыть сайт",delegate { if(passkeyList.SelectedItems.Count>0) OpenPasskeySite("https://"+((LoginEntry)passkeyList.SelectedItems[0].Tag).Target+"/"); }));
            bar.Controls.Add(FeatureButton("Открыть базу",delegate { if(NeedVault()) RefreshPasskeys(); }));
            bar.Controls.Add(FeatureButton("Обновить",RefreshPasskeys));
            bar.Controls.Add(FeatureButton("Удалить ключ",delegate {
                if(vault==null || passkeyList.SelectedItems.Count==0) return;
                var entry=(LoginEntry)passkeyList.SelectedItems[0].Tag;
                if(MessageBox.Show(this,"Удалить ключ доступа для "+entry.Target+" ("+entry.Login+")?\nВход этим ключом станет недоступен.","WinUp",MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
                var current=vault;
                current.Entries.Remove(entry); if(SaveVault()) { entry.ClearSecrets(); RefreshPasskeys(); }
                else { if(vault==current) current.Entries.Add(entry); else entry.ClearSecrets(); RefreshPasskeys(); }
            }));
            page.Controls.Add(passkeyList); page.Controls.Add(bar);
            ArrangeActions(page,new[]{bar},new ActionGroup("Вход",Actions(bar,"Открыть сайт","Открыть базу","Обновить")),new ActionGroup("Ключи",Actions(bar,"Добавить ключ…","Удалить ключ")));
            tabs.TabPages.Add(page);
        }
        void AddPasskeyFromSite() {
            if(!NeedVault()) return;
            using(var dialog=new AddPasskeyDialog(store,vault.Entries)) {
                if(dialog.ShowDialog(this)!=DialogResult.OK) return;
                BrowserSetup.Connect();
                if(!OpenPasskeySite(dialog.Url))return;
                MessageBox.Show(this,"На сайте откройте безопасность аккаунта и создайте ключ доступа. Расширение WinUp предложит сохранить его в этой базе.\n\nЕсли расширение только что обновлено, перезагрузите его и вкладку сайта. Ключи, созданные ранее в Windows или телефоне, остаются у своего провайдера — для WinUp создаётся отдельный ключ.","WinUp — ключ доступа");
            }
        }
        bool OpenPasskeySite(string address) {
            try {
                var browser=Browsers.Find(PreferredBrowser);
                if(!string.IsNullOrWhiteSpace(PreferredBrowser) && browser==null)throw new InvalidOperationException("Выбранный браузер не найден. Выберите установленный браузер во вкладке «Пароли».");
                System.Diagnostics.Process.Start(BrowserPages.SiteLaunch(address,browser));return true;
            } catch(Exception ex) {MessageBox.Show(this,ex.Message,"WinUp — ключ доступа",MessageBoxButtons.OK,MessageBoxIcon.Information);return false;}
        }
        void RefreshPasskeys() {
            passkeyList.Items.Clear(); if(vault==null) return;
            foreach(var entry in vault.Entries.Where(x=>x.Kind=="passkey").OrderBy(x=>x.Target))
                passkeyList.Items.Add(new ListViewItem(new[] {entry.Target,entry.Login}) {Tag=entry});
        }
        internal bool VerifyBrowserUser(string title) {
            var current=vault; if(current==null) return false;
            if(WindowsHello.Enabled) {
                IntPtr hwnd=Handle; HelloResult status=HelloResult.Broken;
                byte[] verified=Busy(delegate { HelloResult r; var bytes=WindowsHello.Unseal(hwnd,title,out r); status=r; return bytes; });
                try {
                    if(status==HelloResult.Cancelled || vault!=current) return false;
                    if(status==HelloResult.Ok && verified!=null) {
                        byte[] expected=current.KeyMaterial();
                        try { if(verified.SequenceEqual(expected)) return true; }
                        finally { Array.Clear(expected,0,expected.Length); }
                    }
                } finally { if(verified!=null) Array.Clear(verified,0,verified.Length); }
            }
            return ConfirmDbPassword(title) && vault==current;
        }
        internal bool SaveBrowserVault() { bool result=SaveVault(); RefreshPasskeys(); return result; }
    }
    sealed class FileVaultChoiceDialog : Dlg {
        public FileVaultChoiceDialog(string selected) : base("Файловое хранилище закрыто") {
            Note("Файлы шифруются внутри хранилища Cryptomator. Выберите, куда их добавить.");
            if(selected!=null) Note("Выбрано: "+selected);
            var open=new Button {Text=selected==null ? "Выбрать существующее" : "Открыть выбранное",AutoSize=true,DialogResult=DialogResult.No};
            var create=new Button {Text="Создать новое",AutoSize=true,DialogResult=DialogResult.Yes};
            Buttons(open,create); Ok.Visible=false;
        }
    }
    sealed class AddPasskeyDialog : Dlg {
        readonly ComboBox service=new ComboBox {DropDownStyle=ComboBoxStyle.DropDown,Width=400};
        public string Url {get { string value=service.Text.Trim(); if(value=="Google") return "https://myaccount.google.com/signinoptions/passkeys"; if(value=="GitHub") return "https://github.com/settings/security"; if(!value.Contains("://")) value="https://"+value; return value; }}
        public AddPasskeyDialog(AppStore store,IEnumerable<LoginEntry> entries) : base("Добавить ключ доступа") {
            service.Items.Add("Google"); service.Items.Add("GitHub");
            foreach(string url in entries.Where(x=>x.Kind=="site" || x.Kind=="both").Select(x=>x.Target).Concat(store.Templates.Where(x=>x.Kind!="app").Select(x=>x.Target)).Where(x=>!string.IsNullOrWhiteSpace(x)).Distinct()) service.Items.Add(url);
            service.SelectedIndex=0; Row("Сервис или HTTPS-адрес:",service);
            Note("Ключ регистрируется на сайте и сохраняется в открытой базе WinUp через своё расширение. Подтверждение — Windows Hello или пароль базы.");
            Buttons(); Ok.Text="Открыть и добавить";
            Ok.Click+=(s,e)=> { Uri uri; if(!Uri.TryCreate(Url,UriKind.Absolute,out uri) || uri.Scheme!="https" || uri.UserInfo.Length>0) { DialogResult=DialogResult.None; MessageBox.Show(this,"Укажите HTTPS-адрес сервиса.","WinUp"); }};
        }
    }
    sealed class FileProgressDialog : Dlg {
        readonly Timer timer=new Timer { Interval=100 };
        public FileProgressDialog(System.Threading.Tasks.Task task,Action cancel) : base("WinUp — файлы") {
            var label=new Label { Text="Выполняю операцию…",AutoSize=true };
            Row("",label); Buttons(); Ok.Visible=false; Cancel.Text="Отменить"; Cancel.DialogResult=DialogResult.None;
            bool cancelled=false;
            Action requestCancel=delegate { if(cancelled) return; cancelled=true; cancel(); Cancel.Enabled=false; label.Text="Отменяю операцию…"; };
            Cancel.Click+=(s,e)=>requestCancel();
            FormClosing+=(s,e)=> { if(!task.IsCompleted) { e.Cancel=true; requestCancel(); } };
            timer.Tick+=(s,e)=> { if(task.IsCompleted) Close(); }; timer.Start();
            FormClosed+=(s,e)=>timer.Dispose();
        }
    }
    sealed class FeatureNameDialog : Dlg, IFileSecretDialog {
        readonly TextBox text=new TextBox { Width=380 };
        public string Value { get { return text.Text.Trim(); } }
        public FeatureNameDialog(string title,string label) : base(title) {
            Row(label,text); Buttons();
            Ok.Click+=(s,e)=> { if(Value.Length==0 || Value=="." || Value==".." || Value.IndexOfAny(Path.GetInvalidFileNameChars())>=0) {
                DialogResult=DialogResult.None; MessageBox.Show(this,"Введите допустимое название.","WinUp");
            }};
        }
    }
    sealed class FileVaultDialog : Dlg, IFileSecretDialog {
        readonly TextBox folder=new TextBox { Width=380 };
        readonly TextBox password=new TextBox { Width=380,UseSystemPasswordChar=true };
        readonly TextBox repeat=new TextBox { Width=380,UseSystemPasswordChar=true };
        public string Folder { get { return folder.Text.Trim(); } }
        public string Password { get { return password.Text; } }
        public FileVaultDialog(bool create,string path=null) : base(create ? "Создать файловое хранилище" : "Открыть файловое хранилище") {
            folder.Text=path ?? Path.Combine(Paths.Root,"files","Хранилище"); folder.ReadOnly=!create;
            Row("Папка хранилища:",folder);
            if(create) {
                var choose=new Button { Text="Выбрать папку…",AutoSize=true };
                choose.Click+=(s,e)=> { using(var d=new FolderBrowserDialog { Description="Выберите родительскую папку" })
                    if(d.ShowDialog(this)==DialogResult.OK) folder.Text=Path.Combine(d.SelectedPath,"Хранилище"); };
                Row("",choose);
            }
            Row("Пароль хранилища:",password); if(create) Row("Повторите пароль:",repeat); Buttons();
            Ok.Click+=(s,e)=> {
                string error=null;
                if(!Path.IsPathRooted(Folder)) error="Укажите полный путь к папке.";
                else if(create && (Directory.Exists(Folder) || File.Exists(Folder))) error="Выберите новое имя папки. Существующие файлы не заменяются.";
                else if(create && password.Text!=repeat.Text) error="Пароли не совпадают.";
                else if(create && Strength.Bits(password.Text)<Strength.MinForVault) error="Пароль слишком простой: используйте длинный случайный пароль.";
                else if(password.Text.Length==0) error="Введите пароль.";
                if(error!=null) { DialogResult=DialogResult.None; MessageBox.Show(this,error,"WinUp"); }
            };
        }
    }
}

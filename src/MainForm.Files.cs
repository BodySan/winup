using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace WinUp {
    partial class MainForm {
        static void AddFileMenu(ContextMenuStrip menu,string text,Action action){var item=menu.Items.Add(text);item.Click+=(s,e)=>{try{action();}catch(Exception ex){MessageBox.Show(ex.Message,"WinUp — файлы");}};}
        bool TryCloseFileVault() {
            var client=fileVault;if(client==null)return true;if(fileBusy)return false;
            if(!client.Open){CloseFileVault();return true;}
            string historyWarning=null;
            bool success=FileOperation(delegate{
                client.UnmountSafely();
                if(!client.ReadOnly&&filePreferences.History)try{client.Call("snapshot",((long)filePreferences.HistoryMiB*1024*1024).ToString(),filePreferences.HistoryKeep.ToString());}catch(IOException ex){historyWarning=ex.Message;}
                client.Call("close");
            },false);
            if(success){CloseFileVault();if(historyWarning!=null)MessageBox.Show(this,"Хранилище закрыто. Новая версия не создана; прежние версии сохранены.\nПроверьте лимит истории и свободное место.\n"+historyWarning,"WinUp — история");return true;}return false;
        }
        bool Checkpoint(bool force) {
            if(fileVault==null)return false;
            if(fileVault.ReadOnly){if(force)MessageBox.Show(this,"Сохранение версии недоступно в режиме чтения.","WinUp — история");return !force;}
            if(!force&&!filePreferences.History)return true;
            var client=fileVault;bool result=FileOperation(delegate{
                client.UnmountSafely();client.Call("snapshot",((long)filePreferences.HistoryMiB*1024*1024).ToString(),filePreferences.HistoryKeep.ToString());
            });if(result)fileHistoryAt=DateTime.UtcNow;return result;
        }
        bool BeforeFileChange(){if(fileVault.ReadOnly){MessageBox.Show(this,"Хранилище открыто только для чтения. Измените настройку и откройте его заново.","WinUp");return false;}return Checkpoint(false);}
        void SaveFileCheckpoint(){if(EnsureFileVault()&&Checkpoint(true)){RefreshFileItems();MessageBox.Show(this,"Версия сохранена. Диск отключён; для продолжения работы нажмите «В Проводнике».","WinUp");}}
        void PackExternal(bool folder) {
            if(fileBusy)return;string[] sources;
            if(folder)using(var d=new FolderBrowserDialog{Description="Выберите папку для отдельного шифрования"}){if(d.ShowDialog(this)!=DialogResult.OK)return;sources=new[]{d.SelectedPath};}
            else using(var d=new OpenFileDialog{Multiselect=true,Title="Файлы для отдельного шифрования"}){if(d.ShowDialog(this)!=DialogResult.OK)return;sources=d.FileNames;}
            using(var output=new SaveFileDialog{Filter="Зашифрованный пакет tar.age|*.age",DefaultExt="age",FileName="Пакет.tar.age",Title="Куда сохранить зашифрованный пакет"}) {
                if(output.ShowDialog(this)!=DialogResult.OK)return;
                using(var password=new FilePackagePasswordDialog(true,true)) {
                    if(password.ShowDialog(this)!=DialogResult.OK)return;string pw=password.Password;bool move=password.RemoveOriginals;
                    string package=FilePackages.PackageOutputName(output.FileName);
                    try {if(FileOperation(delegate{FilePackages.Pack(sources,package,pw,move,fileCancellation.Token);},false))MessageBox.Show(this,"Пакет создан и проверен. "+(move?"Исходники удалены после проверки.":"Исходники сохранены.")+FileInteroperability.WritePackageMemo(package),"WinUp");}finally{Secure.Wipe(pw);}
                }
            }
        }
        void UnpackFilePackage() {
            if(fileBusy)return;
            using(var input=new OpenFileDialog{Filter="Зашифрованный пакет|*.age",Title="Выберите пакет для расшифровки"}) {
                if(input.ShowDialog(this)!=DialogResult.OK)return;
                using(var parent=new FolderBrowserDialog{Description="Куда расшифровать пакет (будет создана новая папка)"}) {
                    if(parent.ShowDialog(this)!=DialogResult.OK)return;
                    using(var name=new FeatureNameDialog("Папка результата","Название новой папки:")) {
                        if(name.ShowDialog(this)!=DialogResult.OK)return;string output=Path.Combine(parent.SelectedPath,name.Value);
                        using(var password=new FilePackagePasswordDialog(false,false)) {
                            if(password.ShowDialog(this)!=DialogResult.OK)return;string pw=password.Password;
                            try {if(FileOperation(delegate{FilePackages.Unpack(input.FileName,output,pw,fileCancellation.Token);},false)) {
                                if(fileVault!=null&&!fileVault.ReadOnly && MessageBox.Show(this,"Пакет проверен и расшифрован. Добавить полученную папку в открытое хранилище?\nПри переносе обычная папка будет удалена после проверки.","WinUp",MessageBoxButtons.YesNo)==DialogResult.Yes)ImportPaths(new[]{output});
                                else MessageBox.Show(this,"Готово. Расшифрованные данные находятся в:\n"+output,"WinUp");
                            }}finally{Secure.Wipe(pw);}
                        }
                    }
                }
            }
        }
        void VerifyFilePackage() {
            if(fileBusy)return;using(var input=new OpenFileDialog{Filter="Зашифрованный пакет|*.age"}) {
                if(input.ShowDialog(this)!=DialogResult.OK)return;
                using(var password=new FilePackagePasswordDialog(false,false)){if(password.ShowDialog(this)!=DialogResult.OK)return;string pw=password.Password;
                    try{if(FileOperation(delegate{FilePackages.Verify(input.FileName,pw,fileCancellation.Token);},false))MessageBox.Show(this,"Пакет полностью прочитан и проверен. Файлы на диск не извлекались.","WinUp");}finally{Secure.Wipe(pw);}}
            }
        }
        void ExportFileSelection() {
            if(!EnsureFileVault()||fileItems.SelectedItems.Count==0){MessageBox.Show(this,"Выберите файлы или папки в списке.","WinUp");return;}
            if(fileVault.MountPoint==null){MountFileVault();if(fileVault.MountPoint==null)return;}
            var sources=fileItems.SelectedItems.Cast<ListViewItem>().Select(x=>SafePaths.Child(fileVault.MountPoint,FileNameInVault(x.Text))).ToArray();
            var client=fileVault;var zones=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            string[] selectedPaths=fileItems.SelectedItems.Cast<ListViewItem>().Select(x=>FileNameInVault(x.Text)).ToArray();
            if(!FileOperation(delegate{foreach(string selected in selectedPaths){var reply=client.Call("zones",selected);foreach(var pair in (Dictionary<string,object>)reply["zones"])zones[SafePaths.Child(client.MountPoint,pair.Key)]=(string)pair.Value;}}))return;
            Func<string,string> zoneLookup=delegate(string path){string value;return zones.TryGetValue(path,out value)?value:null;};
            using(var mode=new FileExportModeDialog()) {
                if(mode.ShowDialog(this)!=DialogResult.OK)return;
                if(mode.Encrypted) {
                    using(var output=new SaveFileDialog{Filter="Зашифрованный пакет tar.age|*.age",DefaultExt="age",FileName="Пакет.tar.age"}) {
                        if(output.ShowDialog(this)!=DialogResult.OK)return;
                        using(var password=new FilePackagePasswordDialog(true,false)) {
                            if(password.ShowDialog(this)!=DialogResult.OK)return;string pw=password.Password;
                            string package=FilePackages.PackageOutputName(output.FileName);
                            try{if(FileOperation(delegate{FilePackages.Pack(sources,package,pw,false,fileCancellation.Token,zoneLookup);},false))MessageBox.Show(this,"Выбранные данные выгружены в отдельный проверенный пакет. Остальное хранилище в него не попало."+FileInteroperability.WritePackageMemo(package),"WinUp");}finally{Secure.Wipe(pw);}
                        }
                    }
                }else using(var folder=new FolderBrowserDialog{Description="Куда выгрузить обычные незашифрованные копии"}){
                    if(folder.ShowDialog(this)!=DialogResult.OK)return;
                    if(FileOperation(delegate{foreach(string src in sources)PlainFileCopy.Copy(src,Path.Combine(folder.SelectedPath,Path.GetFileName(src)),fileCancellation.Token,zoneLookup);},false))MessageBox.Show(this,"Обычные копии сохранены. В выбранной папке они доступны без пароля.","WinUp");
                }
            }
        }
        void BackupFileVault() {
            if(fileBusy||fileCatalog.SelectedItem==null)return;string source=(string)fileCatalog.SelectedItem;
            if(!TryCloseFileVault())return;
            using(var parent=new FolderBrowserDialog{Description="Резерв или перенос: выберите папку за пределами хранилища"}) {
                if(parent.ShowDialog(this)!=DialogResult.OK)return;string output=Path.Combine(parent.SelectedPath,Path.GetFileName(source)+" — резерв "+DateTime.Now.ToString("yyyyMMdd-HHmmss"));
                if(FileOperation(delegate{FilePackages.BackupVault(source,output,fileCancellation.Token);FilePackages.VerifyBackup(output,fileCancellation.Token);},false))
                    MessageBox.Show(this,"Зашифрованная копия создана и проверена:\n"+output+"\n\nНа другом ПК: WinUp → Файлы → Добавить существующее → выбрать эту папку → Открыть. Нужен прежний пароль. Для Проводника нужен WinFsp.","WinUp");
            }
        }
        void VerifyFileBackup(){if(fileBusy)return;using(var d=new FolderBrowserDialog{Description="Папка резервной копии"}){if(d.ShowDialog(this)==DialogResult.OK&&FileOperation(delegate{FilePackages.VerifyBackup(d.SelectedPath,fileCancellation.Token);},false))MessageBox.Show(this,"Состав и контрольные суммы резервной копии проверены. Для проверки пароля откройте копию через «Добавить существующее».","WinUp");}}
        void AutoBackupBeforeOpen(string source,CancellationToken token) {
            string parent=filePreferences.BackupFolder;
            if(string.IsNullOrEmpty(parent))throw new IOException("Выберите папку автоматического резерва в настройках хранилища.");
            Directory.CreateDirectory(parent);
            string output=Path.Combine(parent,"WinUp-"+Path.GetFileName(source)+"-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,8));
            FilePackages.BackupVault(source,output,token);FilePackages.VerifyBackup(output,token);
        }
        void DeleteFileSelection() {
            if(!EnsureFileVault()||fileItems.SelectedItems.Count==0)return;
            if(MessageBox.Show(this,"Удалить выбранные данные? При включённой истории перед удалением будет сохранена версия.","WinUp",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;
            string[] paths=fileItems.SelectedItems.Cast<ListViewItem>().Select(x=>FileNameInVault(x.Text)).ToArray();if(!BeforeFileChange())return;
            var client=fileVault;FileOperation(delegate{foreach(string path in paths)client.Call("delete",path);});RefreshFileItems();
        }
        void ShowFileHistory() {
            if(!EnsureFileVault())return;var client=fileVault;Dictionary<string,object> history=null;
            if(!FileOperation(delegate{history=client.Call("history");}))return;
            using(var dialog=new FileHistoryDialog(client,(ArrayList)history["items"])) {
                if(dialog.ShowDialog(this)!=DialogResult.OK)return;
                if(!BeforeFileChange())return;
                FileOperation(delegate{client.Call("history-restore",dialog.Id,dialog.Relative,dialog.Destination);});RefreshFileItems();
            }
        }
        void ConfigureFileVault(){if(fileBusy||fileCatalog.SelectedItem==null){MessageBox.Show(this,"Сначала выберите хранилище.","WinUp");return;}string folder=(string)fileCatalog.SelectedItem;
            using(var dialog=new FilePreferencesDialog(FileVaultPreferences.Load(folder))){if(dialog.ShowDialog(this)!=DialogResult.OK)return;if(!TryCloseFileVault())return;dialog.Value.Save(folder);filePreferences=dialog.Value;MessageBox.Show(this,"Настройки сохранены. Откройте хранилище заново, чтобы применить режим чтения и букву диска.","WinUp");}}
        void CopyProjectPath(){if(!EnsureFileVault())return;if(fileVault.MountPoint==null)MountFileVault();if(fileVault.MountPoint!=null)Clipboard.SetText(fileVault.MountPoint);}
        void OpenProjectEditor(){if(!EnsureFileVault())return;if(filePreferences.Editor==""){ConfigureFileVault();return;}if(fileVault.MountPoint==null)MountFileVault();if(fileVault.MountPoint!=null)Process.Start(new ProcessStartInfo(filePreferences.Editor,"\""+fileVault.MountPoint+"\""){UseShellExecute=false});}
    }
    internal static class PlainFileCopy {
        internal static void Copy(string source,string output,CancellationToken cancel,Func<string,string> zoneLookup=null){
            source=Path.GetFullPath(source);output=Path.GetFullPath(output);SafePaths.NoReparseParents(output);
            if(SafePaths.IsWithin(output,source))throw new IOException("Выберите папку вне источника.");
            if(File.Exists(output)||Directory.Exists(output))throw new IOException("Такое имя уже существует: "+output);
            string stage=Path.Combine(Path.GetDirectoryName(output),".winup-copy-"+Guid.NewGuid().ToString("N"));
            using(var lease=SourceLease.Acquire(source,false))using(var parent=SourceLease.HoldDirectories(Path.GetDirectoryName(output)))try{
                foreach(string relative in lease.Snapshot){cancel.ThrowIfCancellationRequested();string src=relative==""?source:SafePaths.Child(source,relative),dst=relative==""?stage:SafePaths.Child(stage,relative);
                    if(Directory.Exists(SafePaths.Native(src))){Directory.CreateDirectory(SafePaths.Native(dst));continue;}
                    using(var input=File.OpenRead(SafePaths.Native(src)))using(var target=new FileStream(SafePaths.Native(dst),FileMode.CreateNew,FileAccess.Write,FileShare.None)){input.CopyTo(target);target.Flush(true);}
                    using(var sha=System.Security.Cryptography.SHA256.Create())using(var input=File.OpenRead(SafePaths.Native(src)))using(var copied=File.OpenRead(SafePaths.Native(dst))){if(!sha.ComputeHash(input).SequenceEqual(sha.ComputeHash(copied)))throw new IOException("Проверка копии не пройдена.");}
                    string zone=lease.ZoneFor(relative)??(zoneLookup==null?null:zoneLookup(src));if(zone!=null)FilePackages.WriteZone(dst,Convert.FromBase64String(zone));
                }
                cancel.ThrowIfCancellationRequested();if(Directory.Exists(SafePaths.Native(stage)))Directory.Move(SafePaths.Native(stage),SafePaths.Native(output));else File.Move(SafePaths.Native(stage),SafePaths.Native(output));
            }finally{if(File.Exists(SafePaths.Native(stage)))File.Delete(SafePaths.Native(stage));FilePackages.RemoveOwnedStage(stage,Path.GetDirectoryName(output));}
        }
    }
}

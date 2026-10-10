using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace WinUp {
    sealed class FileCredentialDialog:Dlg,IFileSecretDialog {
        readonly TextBox input=new TextBox{Width=410,UseSystemPasswordChar=true,MaxLength=4096},replacement=new TextBox{Width=410,UseSystemPasswordChar=true,MaxLength=4096},repeat=new TextBox{Width=410,UseSystemPasswordChar=true,MaxLength=4096};
        internal string Input{get{return input.Text;}}internal string Replacement{get{return replacement.Text;}}
        internal FileCredentialDialog(string mode,string folder):base(mode=="recovery-key"?"Ключ восстановления хранилища":mode=="repair"?"Исправить копию хранилища":mode=="health"?"Проверить хранилище":mode=="reset-password"?"Восстановить пароль хранилища":"Сменить пароль хранилища"){
            Note("Хранилище: "+folder+"\nДля этой операции оно будет закрыто. Пароли и ключ не сохраняются в настройках.");
            Row(mode=="reset-password"?"Ключ восстановления:":"Текущий пароль:",input);
            if(mode=="change-password"||mode=="reset-password"){
                Row("Новый пароль:",replacement);Row("Повторите:",repeat);Note("Старые резервные копии продолжают открываться старым паролем. Ключ восстановления сохраняет силу после смены пароля.");
            }else if(mode=="health")Note("Проверяется структура зашифрованного хранилища штатными проверками CryptoFS. Это не проверка содержимого каждого документа. Исправления автоматически не выполняются.");
            else if(mode=="repair")Note("WinUp создаст отдельную зашифрованную копию и применит к ней доступные исправления Cryptomator. Исходное хранилище останется на месте. Утраченные байты документов восстановить таким способом нельзя: для них нужна резервная копия.");
            Buttons();Ok.Click+=(s,e)=>{if(input.Text.Length==0)Fail("Введите пароль или ключ восстановления.");else if(mode=="change-password"||mode=="reset-password"){if(replacement.Text!=repeat.Text)Fail("Новые пароли не совпадают.");else if(Strength.Bits(replacement.Text)<Strength.MinForVault)Fail("Используйте длинный случайный пароль.");}};
        }
    }
    sealed class FileRecoveryDialog:Dlg,IFileSecretDialog {
        internal FileRecoveryDialog(string key):base("Ключ восстановления Cryptomator"){
            Note("Сохраните эти слова отдельно от хранилища. Они позволяют задать новый пароль и остаются действительными после его смены. Этот ключ подходит для восстановления в WinUp и Cryptomator.");
            var text=new TextBox{ReadOnly=true,Multiline=true,Width=480,Height=140,ScrollBars=ScrollBars.Vertical};Row("Ключ:",text);text.Text=key;
            var copy=new Button{Text="Скопировать ключ",AutoSize=true};copy.Click+=(s,e)=>SecureClip.Copy(text.Text);Row("",copy);Buttons();Ok.Text="Сохранил — закрыть";Cancel.Visible=false;
        }
    }
    sealed class FileHealthDialog:Dlg,IFileSecretDialog {
        internal FileHealthDialog(string report,bool repaired=false):base(repaired?"Результат исправления копии":"Результат проверки хранилища"){
            Note(repaired?"Исправления выполнены в отдельной копии. Проверьте нужные документы перед её использованием. Исходное хранилище сохранено.":"Проверка не меняет хранилище. При предупреждениях сначала сделайте зашифрованную резервную копию. Успешная проверка структуры не заменяет резервирование.");
            var text=new TextBox{ReadOnly=true,Multiline=true,Width=570,Height=260,ScrollBars=ScrollBars.Both};FullRow(text);text.Text=report;
            var bar=new FlowLayoutPanel{AutoSize=true};FullRow(bar);Button copy=new Button{Text="Скопировать отчёт",AutoSize=true},save=new Button{Text="Сохранить отчёт…",AutoSize=true};bar.Controls.Add(copy);bar.Controls.Add(save);
            copy.Click+=(s,e)=>Clipboard.SetText(text.Text);save.Click+=(s,e)=>{using(var picker=new SaveFileDialog{Filter="Текстовый отчёт|*.txt",FileName="Проверка хранилища.txt"})if(picker.ShowDialog(this)==DialogResult.OK)try{File.WriteAllText(picker.FileName,text.Text,new UTF8Encoding(false));}catch(Exception ex){MessageBox.Show(this,ex.Message,Text);}};Buttons();Ok.Text="Закрыть";Cancel.Visible=false;
        }
    }
    partial class MainForm {
        void ManageFileVault(string mode){
            if(fileBusy)return;string folder=fileVault!=null?fileVault.Folder:fileCatalog.SelectedItem as string;if(folder==null){MessageBox.Show(this,"Сначала выберите файловое хранилище.","WinUp");return;}
            using(var dialog=new FileCredentialDialog(mode,folder)){
                if(dialog.ShowDialog(this)!=DialogResult.OK||IsDisposed)return;
                string input=dialog.Input,replacement=dialog.Replacement,repairCopy=null;Dictionary<string,object> result=null;
                try{
                    if(fileVault!=null&&!TryCloseFileVault())return;
                    if(mode=="repair"){using(var picker=new FolderBrowserDialog{Description="Где создать исправленную копию хранилища",ShowNewFolderButton=true}){if(picker.ShowDialog(this)!=DialogResult.OK||IsDisposed)return;repairCopy=Path.Combine(picker.SelectedPath,Path.GetFileName(folder)+" — восстановление "+DateTime.Now.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,6));}}
                    bool success=FileOperation(()=>{string target=folder;if(repairCopy!=null){using(var check=new FileVaultClient(folder,"",false,fileCancellation.Token,false,true))check.Call("health",input);PlainFileCopy.Copy(folder,repairCopy,fileCancellation.Token);File.WriteAllText(Path.Combine(repairCopy,".winup-repair-copy"),"WUR1:"+Guid.NewGuid().ToString("N"),new UTF8Encoding(false));target=repairCopy;}using(var client=new FileVaultClient(target,"",false,fileCancellation.Token,false,true))using(fileCancellation.Token.Register(client.Cancel))result=client.Call(mode,input,replacement);},false);
                    if(!success||result==null){if(repairCopy!=null&&Directory.Exists(repairCopy))MessageBox.Show(this,"Исправление не завершено. Исходное хранилище не изменено. Незавершённая копия находится здесь:\n"+repairCopy+"\nНе заменяйте ей исходное хранилище.","WinUp — файлы");return;}
                    if(mode=="recovery-key"){
                        string key=(string)result["key"];result["key"]=null;try{using(var view=new FileRecoveryDialog(key))view.ShowDialog(this);}finally{Secure.Wipe(key);}
                    }else if(mode=="health")using(var view=new FileHealthDialog(HealthReport(folder,result)))view.ShowDialog(this);
                    else if(mode=="repair"){RememberFileVault(repairCopy);fileCatalog.SelectedItem=repairCopy;using(var view=new FileHealthDialog(HealthReport(repairCopy,result),true))view.ShowDialog(this);}
                    else MessageBox.Show(this,"Пароль изменён. Хранилище закрыто; откройте его новым паролем. Зашифрованная копия прежнего masterkey сохранена в папке хранилища. Она и старые резервные копии открываются старым паролем.","WinUp — файлы");
                }finally{Secure.Wipe(input);Secure.Wipe(replacement);}
            }
        }
        internal static string HealthReport(string folder,Dictionary<string,object> result){
            var report=new StringBuilder();report.AppendLine("Хранилище: "+folder);report.AppendLine("Проверок структуры CryptoFS: "+result["checks"]);report.AppendLine("Исправных объектов: "+result["good"]+"; замечаний: "+result["info"]+"; предупреждений: "+result["warnings"]+"; критических ошибок: "+result["critical"]);
            foreach(Dictionary<string,object> row in (ArrayList)result["results"]){report.AppendLine();report.AppendLine("["+row["severity"]+"] "+row["check"]+": "+row["message"]);foreach(var detail in (Dictionary<string,object>)row["details"])report.AppendLine("  "+detail.Key+": "+detail.Value);}
            if((bool)result["truncated"])report.AppendLine("Показаны первые 1000 замечаний; итоговые счётчики учитывают все результаты.");
            report.AppendLine();if(result.ContainsKey("fixed")){report.AppendLine("Выполнено исправлений: "+result["fixed"]+". Результаты выше относятся к повторной проверке копии.");foreach(var failed in (ArrayList)result["failedFixes"])report.AppendLine("Не удалось исправить: "+failed);report.AppendLine("Исходное хранилище сохранено. Проверьте нужные файлы в копии. Некоторые восстановленные файлы могут оказаться в каталоге LOST+FOUND с новыми именами.");}else report.AppendLine("Это проверка структуры, без автоматических исправлений.");report.AppendLine("Содержимое каждого файла отдельно не проверялось.");return report.ToString();
        }
    }
}

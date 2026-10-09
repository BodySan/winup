using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace WinUp {
    sealed class FileImportModeDialog:Dlg {
        readonly RadioButton move=new RadioButton{Text="Перенести: удалить исходники после проверки",AutoSize=true};
        internal bool MoveOriginals{get{return move.Checked;}}
        public FileImportModeDialog():base("Добавить в хранилище"){
            Row("Операция:",new RadioButton{Text="Копировать: оставить исходники",AutoSize=true,Checked=true});Row("",move);
            Row("",new Label{Text="Шифрование не удаляет старые резервные копии исходников.",AutoSize=true});Buttons();Ok.Text="Добавить";
        }
    }
    sealed class FileExportModeDialog:Dlg {
        readonly RadioButton encrypted=new RadioButton{Text="Зашифрованный пакет с отдельным паролем",AutoSize=true,Checked=true};
        internal bool Encrypted{get{return encrypted.Checked;}}
        public FileExportModeDialog():base("Выгрузить выбранное"){
            Row("Формат:",encrypted);Row("",new RadioButton{Text="Обычная копия: доступна без пароля",AutoSize=true});Buttons();
        }
    }
    sealed class FilePackagePasswordDialog:Dlg,IFileSecretDialog {
        readonly TextBox password=new TextBox{Width=360,UseSystemPasswordChar=true};
        readonly TextBox repeat=new TextBox{Width=360,UseSystemPasswordChar=true};
        readonly CheckBox remove=new CheckBox{Text="Удалить исходники после проверки пакета",AutoSize=true};
        internal string Password{get{return password.Text;}}
        internal bool RemoveOriginals{get{return remove.Checked;}}
        public FilePackagePasswordDialog(bool create,bool canRemove):base(create?"Пароль отдельного пакета":"Открыть зашифрованный пакет"){
            Row("Пароль:",password);if(create)Row("Повторите:",repeat);
            if(canRemove)Row("",remove);
            Row("",new Label{Text="Пароль пакета независим от пароля хранилища.\nЗабытый пароль восстановить нельзя.",AutoSize=true});Buttons();
            Ok.Click+=(s,e)=>{
                string error=null;if(Password.Length==0)error="Введите пароль.";
                else if(create&&Password!=repeat.Text)error="Пароли не совпадают.";
                else if(create&&Strength.Bits(Password)<Strength.MinForVault)error="Используйте длинный случайный пароль.";
                if(error!=null){DialogResult=DialogResult.None;MessageBox.Show(this,error,"WinUp");}
            };
        }
    }
    sealed class FilePreferencesDialog:Dlg {
        readonly ComboBox drive=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=200};
        readonly CheckBox read=new CheckBox{Text="Открывать только для чтения",AutoSize=true};
        readonly CheckBox history=new CheckBox{Text="Сохранять версии при операциях WinUp и подключении диска",AutoSize=true};
        readonly NumericUpDown mib=new NumericUpDown{Minimum=16,Maximum=102400,Width=130};
        readonly NumericUpDown count=new NumericUpDown{Minimum=1,Maximum=100,Width=130};
        readonly CheckBox backup=new CheckBox{Text="Резерв перед каждым открытием (зашифрованная копия)",AutoSize=true};
        readonly TextBox parent=new TextBox{Width=360};
        readonly TextBox editor=new TextBox{Width=360};
        readonly CheckBox project=new CheckBox{Text="Режим проекта: отдельный срок автоматического закрытия",AutoSize=true};
        readonly NumericUpDown idle=new NumericUpDown{Minimum=1,Maximum=1440,Width=130};
        internal FileVaultPreferences Value{get;private set;}
        public FilePreferencesDialog(FileVaultPreferences p):base("Настройки хранилища и проекта"){
            Grid.ColumnStyles[1].Width=540;
            Value=p;drive.Items.Add("Автоматически");for(char c='D';c<='Z';c++)drive.Items.Add(c+":\\");drive.SelectedItem=p.Drive==""?"Автоматически":p.Drive;
            read.Checked=p.ReadOnly;history.Checked=p.History;mib.Value=p.HistoryMiB;count.Value=p.HistoryKeep;backup.Checked=p.AutoBackup;parent.Text=p.BackupFolder;editor.Text=p.Editor;project.Checked=p.ProjectMode;idle.Value=p.ProjectIdleMinutes;
            Row("Буква диска:",drive);Row("",read);Row("",history);Row("Лимит истории, МиБ:",mib);Row("Максимум версий:",count);
            Row("",backup);Row("Папка резерва:",parent);
            var pick=new Button{Text="Выбрать папку резерва…",AutoSize=true};pick.Click+=(s,e)=>{using(var d=new FolderBrowserDialog()){if(d.ShowDialog(this)==DialogResult.OK)parent.Text=d.SelectedPath;}};Row("",pick);
            Row("EXE редактора:",editor);var choose=new Button{Text="Выбрать редактор…",AutoSize=true};choose.Click+=(s,e)=>{using(var d=new OpenFileDialog{Filter="Программа|*.exe"}){if(d.ShowDialog(this)==DialogResult.OK)editor.Text=d.FileName;}};Row("",choose);
            Row("",project);Row("Простой проекта, мин:",idle);
            Row("",new Label{AutoSize=true,Text="Пароли блокируются по общему таймеру. Проект — по своему.\n«Заблокировать всё» закрывает оба. Резервы автоматически не удаляются.\nПромежуточные изменения в редакторе: сохраняйте версии вручную.\nПеред закрытием проекта сохраните документы в редакторе."});Buttons();
            Ok.Click+=(s,e)=>{try{p.Drive=drive.SelectedIndex==0?"":(string)drive.SelectedItem;p.ReadOnly=read.Checked;p.History=history.Checked;p.HistoryMiB=(int)mib.Value;p.HistoryKeep=(int)count.Value;p.AutoBackup=backup.Checked;p.BackupFolder=parent.Text.Trim();p.Editor=editor.Text.Trim();p.ProjectMode=project.Checked;p.ProjectIdleMinutes=(int)idle.Value;p.Validate();if(p.AutoBackup&&p.BackupFolder=="")throw new IOException("Выберите папку резерва.");}catch(Exception ex){DialogResult=DialogResult.None;MessageBox.Show(this,ex.Message,"WinUp");}};
        }
    }
    sealed class FileHistoryDialog:Dlg {
        readonly ComboBox snapshots=new ComboBox{Width=420,DropDownStyle=ComboBoxStyle.DropDownList};
        readonly ListBox files=new ListBox{Width=500,Height=210};
        readonly TextBox destination=new TextBox{Width=360};
        readonly Dictionary<string,string> ids=new Dictionary<string,string>();
        internal string Id{get{return ids[(string)snapshots.SelectedItem];}}
        internal string Relative{get{return (string)files.SelectedItem;}}
        internal string Destination{get{return destination.Text.Trim().Replace('\\','/');}}
        public FileHistoryDialog(FileVaultClient client,ArrayList items):base("История и восстановление файлов"){
            foreach(Dictionary<string,object> item in items.Cast<Dictionary<string,object>>().Reverse()) {
                string id=(string)item["id"];long ms=long.Parse(id.Substring(0,13));DateTime date=new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddMilliseconds(ms).ToLocalTime();
                string label=date.ToString("yyyy-MM-dd HH:mm:ss")+" · "+Convert.ToInt64(item["size"]).ToString("N0")+" Б · "+id.Substring(14,8);ids[label]=id;snapshots.Items.Add(label);
            }
            Row("Версия:",snapshots);Row("Файл:",files);Row("Сохранить в хранилище:",destination);
            Row("",new Label{Text="Восстановление создаёт новую копию. Существующие файлы не заменяются.\nУдалённые через Проводник файлы доступны в предыдущем снимке.",AutoSize=true});Buttons();Ok.Text="Восстановить";
            snapshots.SelectedIndexChanged+=(s,e)=>{try {files.Items.Clear();var result=client.Call("history-files",Id);foreach(Dictionary<string,object> item in (ArrayList)result["items"])files.Items.Add((string)item["name"]);}catch(Exception ex){MessageBox.Show(this,ex.Message,"WinUp");}};
            files.SelectedIndexChanged+=(s,e)=>{if(files.SelectedItem!=null){string path=(string)files.SelectedItem;string name=Path.GetFileNameWithoutExtension(path)+" — восстановлено "+DateTime.Now.ToString("yyyyMMdd-HHmmss")+Path.GetExtension(path);destination.Text=name;}};
            if(snapshots.Items.Count>0)snapshots.SelectedIndex=0;
            Ok.Click+=(s,e)=>{if(snapshots.SelectedItem==null||files.SelectedItem==null||Destination.Length==0||Destination.Contains(":")||Destination.Split('/').Any(x=>x==".."||x=="."||x==""||x.IndexOfAny(Path.GetInvalidFileNameChars())>=0)){DialogResult=DialogResult.None;MessageBox.Show(this,"Выберите версию, файл и допустимый путь новой копии.","WinUp");}};
        }
    }
}

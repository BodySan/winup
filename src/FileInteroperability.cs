using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace WinUp {
    internal static class FileInteroperability {
        internal const string AgeUrl="https://github.com/FiloSottile/age/releases";
        internal const string VaultUrl="https://cryptomator.org/downloads/";
        static string Literal(string s){return "'"+s.Replace("'","''")+"'";}
        internal static string PackageGuide(string name="Пакет.tar.age") {
            return "КАК ОТКРЫТЬ ПАКЕТ БЕЗ WINUP\r\n\r\n"+
                "Формат: обычный архив tar, зашифрованный стандартным age с паролем. WinUp для открытия не обязателен. Нужны сам пакет, его пароль, age и программа для распаковки tar.\r\n\r\n"+
                "WINDOWS — ПО ШАГАМ\r\n"+
                "1. Создайте новую пустую папку для расшифровки и скопируйте в неё пакет. Оригинал сохраните.\r\n"+
                "2. Установите официальный age: откройте PowerShell и выполните:\r\n   winget install --id FiloSottile.age --exact\r\n"+
                "   Затем откройте PowerShell заново. Без WinGet скачайте ZIP windows-amd64 с "+AgeUrl+" и распакуйте его. Если age.exe лежит рядом с пакетом, вместо age в команде используйте .\\age.exe.\r\n"+
                "3. В Проводнике откройте созданную папку, нажмите адресную строку, введите powershell и нажмите Enter. Выполните:\r\n   age --decrypt --output 'Расшифровано.tar' "+Literal(name)+"\r\n"+
                "   Если пакет переименован, подставьте его настоящее имя вместо имени в последней части команды. age сам попросит пароль. Введите пароль пакета; символы могут не отображаться. Пароль в команду вставлять не нужно.\r\n"+
                "4. Только если age завершился без ошибки, распакуйте результат:\r\n   New-Item -ItemType Directory -Path 'Открыто' -ErrorAction Stop\r\n   tar -xf 'Расшифровано.tar' -C 'Открыто'\r\n"+
                "   Файлы находятся в папке Открыто. Архив tar можно также открыть установленным архиватором с поддержкой tar.\r\n\r\n"+
                "Если имена Расшифровано.tar или Открыто уже заняты, начните в другой новой пустой папке. Если age сообщает об ошибке пароля или повреждении, не распаковывайте промежуточный tar.\r\n\r\n"+
                "macOS / LINUX\r\nУстановите официальный age для своей ОС, выполните age --decrypt --output Расшифровано.tar Пакет.tar.age, затем распакуйте tar в новую пустую папку. Пробелы в именах заключайте в кавычки.\r\n\r\n"+
                "В архиве есть служебный .winup-package.json. Это список содержимого и меток загрузки, а не пароль. Обычные age/tar возвращают файлы и папки, но не восстанавливают эти метки NTFS автоматически; WinUp восстанавливает их при своей расшифровке. Не передавайте расшифрованный tar как зашифрованный файл: пароль уже снят.\r\n\r\n"+
                "Для открытия через WinUp: Файлы → Расшифровать пакет…, выберите пакет, новую папку и введите пароль.\r\n";
        }
        internal static string VaultGuide(){return "КАК ОТКРЫТЬ ХРАНИЛИЩЕ БЕЗ WINUP\r\n\r\n"+
            "Хранилище использует формат Cryptomator 8. Его открывает обычный Cryptomator Desktop. Это другой формат, чем отдельный пакет tar.age.\r\n\r\n"+
            "1. Закройте хранилище в WinUp. Для переноса используйте всю папку хранилища либо резерв из команды Резерв / перенос…. Нужны vault.cryptomator, masterkey.cryptomator и каталог d целиком. Один зашифрованный файл из каталога d открыть отдельно нельзя.\r\n"+
            "2. Установите Cryptomator с "+VaultUrl+".\r\n"+
            "3. Нажмите Добавить хранилище / Add Vault → Открыть существующее / Open Existing Vault. Выберите vault.cryptomator; если диалог просит masterkey.cryptomator, выберите этот файл в той же папке. Создавать новое хранилище поверх прежнего не нужно.\r\n"+
            "4. Нажмите Разблокировать / Unlock и введите пароль именно файлового хранилища. Пароль базы паролей WinUp и пароль отдельного пакета могут отличаться.\r\n"+
            "5. Нажмите Показать диск / Reveal Drive. На открытом диске можно читать, копировать и редактировать файлы. После работы закройте документы и заблокируйте хранилище в Cryptomator.\r\n\r\n"+
            "Не открывайте одну и ту же папку одновременно в WinUp и Cryptomator. История WinUp может отображаться как служебная папка .winup-history; не удаляйте её, если нужны прежние версии. Настройки редактора и буквы диска WinUp в Cryptomator не переносятся.\r\n\r\n"+
            "Для возвращения в WinUp: Файлы → Добавить существующее, выберите папку хранилища и откройте прежним паролем.\r\n";}
        internal static string All(){return PackageGuide()+"\r\n========================================\r\n\r\n"+VaultGuide();}
        internal static string WritePackageMemo(string package){
            string path=package+".README.txt";
            try{SafePaths.NoReparseParents(path);using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read))using(var writer=new StreamWriter(file,new UTF8Encoding(true)))writer.Write(PackageGuide(Path.GetFileName(package)));return " Памятка без WinUp сохранена рядом: "+Path.GetFileName(path);}
            catch(Exception ex){return " Пакет готов. Памятка рядом не сохранена ("+ex.GetType().Name+"); её можно сохранить кнопкой «Без WinUp…».";}
        }
    }
    sealed class FileInteroperabilityDialog:Form {
        internal FileInteroperabilityDialog(){
            Text="Как открыть файлы без WinUp";Size=new Size(850,640);MinimumSize=new Size(600,450);StartPosition=FormStartPosition.CenterParent;Font=new Font("Segoe UI",9);
            var text=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,Text=FileInteroperability.All()};
            Shown+=(s,e)=>{text.SelectionStart=0;text.SelectionLength=0;};
            var bar=new FlowLayoutPanel{Dock=DockStyle.Bottom,AutoSize=true,Padding=new Padding(4)};
            Add(bar,"Скопировать памятку",()=>Clipboard.SetText(text.Text));
            Add(bar,"Сохранить памятку…",()=>{using(var picker=new SaveFileDialog{Filter="Текстовая памятка|*.txt",FileName="Как открыть без WinUp.txt"})if(picker.ShowDialog(this)==DialogResult.OK)File.WriteAllText(picker.FileName,text.Text,new UTF8Encoding(true));});
            Add(bar,"Скачать age",()=>System.Diagnostics.Process.Start(FileInteroperability.AgeUrl));
            Add(bar,"Скачать Cryptomator",()=>System.Diagnostics.Process.Start(FileInteroperability.VaultUrl));
            Add(bar,"Закрыть",Close);Controls.Add(text);Controls.Add(bar);Appearance.Apply(this);
        }
        void Add(FlowLayoutPanel bar,string label,Action action){var button=new Button{Text=label,AutoSize=true};button.Click+=(s,e)=>{try{action();}catch(Exception ex){MessageBox.Show(this,ex.Message,"WinUp");}};bar.Controls.Add(button);}
    }
    partial class MainForm {void ShowFileInteroperability(){using(var dialog=new FileInteroperabilityDialog())dialog.ShowDialog(this);}}
}

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinUp {
    internal sealed class AutoTypeStep {internal string Field,Text;internal ushort Key;internal int Delay,Repeat=1;internal bool Shift,Control;}
    internal static class ApplicationAutoType {
        internal static bool WindowMatches(string pattern,string title){return !string.IsNullOrWhiteSpace(pattern)&&Regex.IsMatch(title??"","^"+Regex.Escape(pattern).Replace("\\*",".*").Replace("\\?",".")+"$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);}
        internal static string SequenceFor(LoginEntry entry,string title){var rule=entry.AutoTypeRules.FirstOrDefault(r=>WindowMatches(r.Window,title));return rule!=null&&!string.IsNullOrEmpty(rule.Sequence)?rule.Sequence:entry.AutoTypeSequence;}
        internal static bool Matches(LoginEntry entry,string title){return entry.AutoTypeRules.Count>0?entry.AutoTypeRules.Any(r=>WindowMatches(r.Window,title)):!string.IsNullOrWhiteSpace(entry.Window)&&entry.Window.Split('|').Any(p=>(title??"").IndexOf(p.Trim(),StringComparison.CurrentCultureIgnoreCase)>=0&&p.Trim().Length>0);}
        internal static List<AutoTypeStep> Parse(string sequence){
            if(string.IsNullOrEmpty(sequence)||sequence.Length>4096)throw new IOException("Введите последовательность, не длиннее 4096 символов.");
            var result=new List<AutoTypeStep>();for(int i=0;i<sequence.Length;){if(sequence[i]!='{'){int start=i;while(i<sequence.Length&&sequence[i]!='{')i++;result.Add(new AutoTypeStep{Text=sequence.Substring(start,i-start)});continue;}
                int end=sequence.IndexOf('}',i+1);if(end<0)throw new IOException("В последовательности не закрыта фигурная скобка.");string token=sequence.Substring(i+1,end-i-1);i=end+1;string upper=token.ToUpperInvariant();
                if(upper=="USERNAME"||upper=="PASSWORD"||upper=="LOGIN2"||upper=="TOTP"||upper.StartsWith("S:")){result.Add(new AutoTypeStep{Field=token});continue;}
                if(upper=="LEFTBRACE"){result.Add(new AutoTypeStep{Text="{"});continue;}if(upper=="RIGHTBRACE"){result.Add(new AutoTypeStep{Text="}"});continue;}
                if(upper.StartsWith("DELAY ")||upper.StartsWith("DELAY=")){int delay;if(!int.TryParse(upper.Substring(6),out delay)||delay<0||delay>10000)throw new IOException("Пауза должна быть от 0 до 10000 миллисекунд.");result.Add(new AutoTypeStep{Delay=delay,Field=upper[5]=='='?"KEYDELAY":null});continue;}
                string[] parts=upper.Split(new[]{' '},StringSplitOptions.RemoveEmptyEntries);int repeat=1;if(parts.Length==0)throw new IOException("Пустая команда в последовательности автоввода.");if(parts.Length>2||(parts.Length==2&&(!int.TryParse(parts[1],out repeat)||repeat<1||repeat>100)))throw new IOException("Число повторений клавиши должно быть от 1 до 100.");string key=parts[0];bool shift=key=="SHIFT+TAB";if(shift)key="TAB";
                ushort vk;switch(key){case "TAB":vk=Win.TAB;break;case "ENTER":vk=Win.ENTER;break;case "ESC":vk=0x1B;break;case "UP":vk=0x26;break;case "DOWN":vk=0x28;break;case "LEFT":vk=0x25;break;case "RIGHT":vk=0x27;break;case "HOME":vk=0x24;break;case "END":vk=0x23;break;case "BACKSPACE":vk=8;break;case "DELETE":vk=0x2E;break;case "SELECTALL":case "CLEARFIELD":vk=0x41;break;default:throw new IOException("Неизвестная команда: {"+token+"}. Используйте команды из подсказки.");}
                result.Add(new AutoTypeStep{Key=vk,Shift=shift,Control=key=="SELECTALL"||key=="CLEARFIELD",Repeat=repeat});if(key=="CLEARFIELD")result.Add(new AutoTypeStep{Key=8});
            }
            if(result.Where(s=>s.Field!="KEYDELAY").Sum(s=>s.Delay)>60000||result.Sum(s=>s.Repeat)>1000)throw new IOException("Последовательность слишком длинная: сократите паузы или повторения.");return result;
        }
        internal static async Task<bool> Run(LoginEntry entry,KdbxStore store,string sequence,IntPtr window,DesktopTarget binding,CancellationToken cancellation){
            var steps=Parse(sequence);int keyDelay=15;long revision=store.RecordRevision;
            Func<bool> valid=()=>{string reason;return !cancellation.IsCancellationRequested&&!store.IsLocked&&store.RecordRevision==revision&&Win.IsForeground(window)&&binding.Verify(window,out reason);};
            foreach(var step in steps){if(!valid())return false;if(step.Field=="KEYDELAY"){keyDelay=step.Delay;continue;}
                if(step.Delay>0){for(int wait=0;wait<step.Delay;wait+=100){await Task.Delay(Math.Min(100,step.Delay-wait));if(!valid())return false;}continue;}
                if(step.Key!=0){for(int repeat=0;repeat<step.Repeat;repeat++){if(!valid()||!Win.Chord(window,step.Key,step.Control,step.Shift))return false;await Task.Delay(Math.Max(1,keyDelay));}continue;}
                string text=step.Text;bool secret=false;
                if(step.Field!=null){string field=step.Field.ToUpperInvariant();if(field=="USERNAME")text=entry.ResolvedLogin;else if(field=="LOGIN2"||field=="S:LOGIN2")text=entry.ResolvedLogin2;else if(field=="PASSWORD"){secret=true;text=entry.UsePassword(p=>new string((p??"").ToCharArray()));}else if(field=="TOTP"){secret=true;var otp=store.Otp.FirstOrDefault(o=>o.Id==entry.OtpId);if(otp==null)throw new IOException("Для {TOTP} выберите связанный аккаунт 2FA.");while(Totp.SecondsLeftFor(otp.Period)<3){await Task.Delay(200);if(!valid())return false;}text=Totp.Code(otp);}else{var extra=entry.CustomFields.FirstOrDefault(f=>f.Name.Equals(step.Field.Substring(2),StringComparison.CurrentCultureIgnoreCase));if(extra==null)throw new IOException("Дополнительное поле не найдено: "+step.Field.Substring(2));secret=true;text=extra.UseResolvedValue(v=>new string((v??"").ToCharArray()));}}
                try{foreach(char c in text??""){if(!valid()||!Win.TypeText(window,c.ToString()))return false;await Task.Delay(Math.Max(1,keyDelay));}}finally{if(secret)Secure.Wipe(text);}
            }return valid();
        }
    }
    sealed class ApplicationAutoTypeDialog:Dlg,ILockableDialog {
        readonly TextBox sequence=new TextBox{Multiline=true,Height=90,MaxLength=4096};
        readonly TextBox rules=new TextBox{Multiline=true,Height=110,ScrollBars=ScrollBars.Vertical,MaxLength=32768};readonly LoginEntry entry;
        internal ApplicationAutoTypeDialog(LoginEntry entry):base("Автоввод в приложение"){
            this.entry=entry;Note("Задайте порядок полей и клавиш. Эта последовательность используется кнопкой «Войти» для приложения и горячей клавишей. Пароль вписывать сюда не нужно.");Row("Последовательность:",sequence);
            Note("{USERNAME} — логин, {PASSWORD} — пароль, {LOGIN2} — дополнительный логин, {TOTP} — связанный код 2FA, {S:Имя} — дополнительное поле.\n{TAB}, {SHIFT+TAB}, {ENTER}, {CLEARFIELD}, стрелки, {HOME}, {END}, {BACKSPACE}, {DELETE}, {ESC}.\n{DELAY 1000} — пауза 1 секунду; {DELAY=50} — интервал между клавишами; {TAB 2} — два Tab. Для фигурных скобок в тексте: {LEFTBRACE} и {RIGHTBRACE}.");
            Row("Правила окон:",rules);Note("По одному правилу в строке: заголовок окна => последовательность. Можно использовать * и ? в заголовке. Пустая последовательность после => берётся из поля выше. Например: *Вход* => {USERNAME}{TAB}{PASSWORD}{ENTER}. Программа дополнительно проверяется по сохранённому пути.");
            sequence.Text=entry.AutoTypeSequence??"";rules.Text=string.Join("\r\n",entry.AutoTypeRules.Select(r=>r.Window+" => "+r.Sequence));Buttons();Ok.Click+=(s,e)=>{try{if(sequence.Text.Length>0)ApplicationAutoType.Parse(sequence.Text);var parsed=new List<AppWindowRule>();foreach(string line in rules.Lines.Where(l=>!string.IsNullOrWhiteSpace(l))){int p=line.IndexOf("=>",StringComparison.Ordinal);if(p<=0)throw new IOException("Разделите заголовок и последовательность знаком =>.");var r=new AppWindowRule{Window=line.Substring(0,p).Trim(),Sequence=line.Substring(p+2).Trim()};if(r.Window.Length==0||r.Window.Length>256)throw new IOException("Заголовок окна должен содержать от 1 до 256 символов.");if(r.Sequence.Length>0)ApplicationAutoType.Parse(r.Sequence);parsed.Add(r);}if(parsed.Count>32)throw new IOException("Можно добавить до 32 правил окон.");entry.AutoTypeSequence=sequence.Text;entry.AutoTypeRules=parsed;}catch(Exception ex){Fail(ex.Message);}};
        }
    }
    partial class MainForm {
        const int AutoTypeHotkeyId=0x5755;bool autoTypeRegistered;
        [DllImport("user32.dll",SetLastError=true)]static extern bool RegisterHotKey(IntPtr h,int id,uint modifiers,uint key);
        [DllImport("user32.dll")]static extern bool UnregisterHotKey(IntPtr h,int id);
        void RegisterAutoTypeHotkey(){if(store==null)return;if(autoTypeRegistered){UnregisterHotKey(Handle,AutoTypeHotkeyId);autoTypeRegistered=false;}if(store.Settings.AutoTypeHotkey!=0){uint modifiers=0;Keys keys=(Keys)store.Settings.AutoTypeHotkey;if((keys&Keys.Control)!=0)modifiers|=2;if((keys&Keys.Alt)!=0)modifiers|=1;if((keys&Keys.Shift)!=0)modifiers|=4;autoTypeRegistered=RegisterHotKey(Handle,AutoTypeHotkeyId,modifiers|0x4000,(uint)(keys&Keys.KeyCode));if(!autoTypeRegistered)PwLog("Горячая клавиша автоввода занята другой программой. Выберите другое сочетание в «Автоввод / горячая клавиша…».");}}
        void EditApplicationAutoType(){var entry=SelectedEntry();if(vault==null||entry==null)return;var current=vault;var copy=entry.Copy();bool kept=false;try{using(var d=new ApplicationAutoTypeDialog(copy)){if(d.ShowDialog(this)!=DialogResult.OK||vault!=current)return;int i=current.Entries.IndexOf(entry);if(i<0)return;current.Entries[i]=copy;if(SaveVault()){kept=true;entry.ClearSecrets();}else if(vault==current&&i<current.Entries.Count)current.Entries[i]=entry;else entry.ClearSecrets();}}finally{if(!kept)copy.ClearSecrets();}}
        async void BeginAutoTypeForeground(){try{await AutoTypeForeground();}catch(Exception ex){PwLog("Автоввод: "+ex.Message);}}
        async Task AutoTypeForeground(){if(vault==null||busyLogin)return;IntPtr window=Win.Foreground;string title=Win.Title(window);var current=vault;
            for(int i=0;i<100&&!Win.ModifiersReleased;i++){await Task.Delay(20);if(vault!=current||busyLogin||!Win.IsForeground(window))return;}if(!Win.ModifiersReleased)return;
            var candidates=new List<LoginEntry>();foreach(var entry in current.Entries.Where(e=>e.Kind=="app"||e.Kind=="both")){string reason;var binding=DesktopTarget.Create(entry.Kind=="app"?entry.Target:entry.AppTarget,out reason);if(binding!=null&&binding.Matches(window)&&ApplicationAutoType.Matches(entry,title))candidates.Add(entry);}
            if(candidates.Count==0){PwLog("Автоввод: для активного окна не найден аккаунт с подходящим правилом и путём приложения.");return;}LoginEntry chosen=candidates[0];
            if(candidates.Count>1){using(var d=new AutoTypeChooseDialog(candidates)){if(d.ShowDialog(this)!=DialogResult.OK||vault!=current)return;chosen=d.Selected;}if(!Win.Focus(window))return;}
            string why;var target=DesktopTarget.Create(chosen.Kind=="app"?chosen.Target:chosen.AppTarget,out why);if(target==null||!target.Verify(window,out why))return;
            busyLogin=true;loginCts=new CancellationTokenSource();var copy=chosen.Copy();try{string sequence=ApplicationAutoType.SequenceFor(copy,title);if(string.IsNullOrEmpty(sequence))sequence=(string.IsNullOrEmpty(copy.Login)?"":"{USERNAME}{TAB}")+"{PASSWORD}"+(copy.AutoEnter?"{ENTER}":"");bool ok=await ApplicationAutoType.Run(copy,current,sequence,window,target,loginCts.Token);PwLog(copy.Name+": "+(ok?"автоввод выполнен.":"автоввод остановлен — окно или состояние базы изменилось."));}catch(Exception ex){PwLog("Автоввод: "+ex.Message);}finally{copy.ClearSecrets();busyLogin=false;loginCts.Dispose();loginCts=null;}
        }
        void ConfigureAutoTypeHotkey(){using(var d=new AutoTypeHotkeyDialog((Keys)store.Settings.AutoTypeHotkey)){if(d.ShowDialog(this)!=DialogResult.OK)return;int old=store.Settings.AutoTypeHotkey;store.Settings.AutoTypeHotkey=(int)d.Value;RegisterAutoTypeHotkey();if(d.Value!=Keys.None&&!autoTypeRegistered){store.Settings.AutoTypeHotkey=old;RegisterAutoTypeHotkey();MessageBox.Show(this,"Сочетание занято. Выберите другое.","WinUp");return;}SaveApps();}}
    }
    sealed class AutoTypeChooseDialog:Dlg,ILockableDialog {
        readonly ComboBox entries=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList};sealed class Item{internal LoginEntry E;public override string ToString(){return E.Name+" — "+AccountOrganization.DisplayLogin(E);}}
        internal LoginEntry Selected{get{return ((Item)entries.SelectedItem).E;}}
        internal AutoTypeChooseDialog(IEnumerable<LoginEntry> source):base("Выберите аккаунт для автоввода"){foreach(var e in source)entries.Items.Add(new Item{E=e});entries.SelectedIndex=0;Row("Аккаунт:",entries);Buttons();}
    }
    sealed class AutoTypeHotkeyDialog:Dlg {
        readonly TextBox input=new TextBox{ReadOnly=true};internal Keys Value;
        internal AutoTypeHotkeyDialog(Keys value):base("Горячая клавиша автоввода"){Value=value;input.Text=value==Keys.None?"Выключено":value.ToString();Row("Сочетание:",input);Note("Нажмите сочетание с Ctrl и Alt или Ctrl и Shift. Оно заполняет активное окно по подходящей записи. При нескольких аккаунтах появится выбор.");var off=new Button{Text="Выключить",AutoSize=true};Row("",off);off.Click+=(s,e)=>{Value=Keys.None;input.Text="Выключено";};input.KeyDown+=(s,e)=>{e.SuppressKeyPress=true;if((e.Modifiers&Keys.Control)!=0&&(e.Modifiers&(Keys.Alt|Keys.Shift))!=0&&e.KeyCode!=Keys.ControlKey&&e.KeyCode!=Keys.ShiftKey&&e.KeyCode!=Keys.Menu){Value=e.KeyData;input.Text=Value.ToString();}};Buttons();}
    }
}

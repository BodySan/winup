using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace WinUp {
 internal static class AdvancedUiProbe {
  const string Password="Synthetic-Advanced-UI-2026!";const BindingFlags Private=BindingFlags.Instance|BindingFlags.NonPublic;static string shots;static int count;
  [STAThread]static int Main(){if(Environment.UserName!="WDAGUtilityAccount"||!Paths.Root.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase))throw new Exception("Synthetic sandbox only");AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib"?CoreLoader.Resolve():EmbeddedModules.Resolve(e.Name);Application.EnableVisualStyles();shots=@"C:\WinUp\test\advanced-1.18\shots";Directory.CreateDirectory(shots);try{Run();Console.WriteLine("RESULT ui-captures="+count+" failed=0");return 0;}catch(Exception ex){Console.WriteLine("FAIL "+ex);return 1;}}
  static IEnumerable<Control> Children(Control parent){foreach(Control child in parent.Controls){yield return child;foreach(var c in Children(child))yield return c;}}
  static void Capture(Form form,string name,Action action=null){Exception error=null;using(var timer=new Timer{Interval=250}){timer.Tick+=(s,e)=>{timer.Stop();try{form.PerformLayout();if(action!=null)action();Application.DoEvents();using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,form.Size));bitmap.Save(Path.Combine(shots,name+".png"));}foreach(var button in Children(form).OfType<Button>().Where(b=>b.Visible)){if(button.Width<20||button.Height<15)throw new Exception("Unreachable button: "+button.Text);}count++;Console.WriteLine("PASS ui "+name);form.DialogResult=DialogResult.Cancel;form.Close();}catch(Exception ex){error=ex;form.Close();}};form.Shown+=(s,e)=>timer.Start();form.ShowDialog();}if(error!=null)throw error;}
  static void Run(){var app=new AppStore{Templates=Defaults.Load().Templates};app.Settings.WizardDone=true;app.Settings.HideFromCapture=false;app.Settings.AutoLockMinutes=1440;app.Settings.BackupDir=Path.Combine(Paths.Root,"backups");app.Save();Win.SetCaptureProtection(false);var db=KdbxStore.Create(Password,null);try{
   string group=db.CreateAccountGroup(null,"Работа");string child=db.CreateAccountGroup(group,"Учебный проект");var entry=new LoginEntry{Name="Учебный аккаунт",Kind="both",Target="https://example.com/",Login="demo@example.com",Password="Synthetic-password!",GroupId=child,Tags=KdbxStore.ParseTags("Проект; Работа"),AppTarget=Application.ExecutablePath,AutoTypeSequence="{USERNAME}{TAB}{PASSWORD}{ENTER}"};entry.AutoTypeRules.Add(new AppWindowRule{Window="*Вход*",Sequence="{USERNAME}{TAB}{PASSWORD}{ENTER}"});db.Entries.Add(entry);db.Entries.Add(new LoginEntry{Name="Второй аккаунт",Kind="site",Target="https://example.org/",Login="other@example.org",Password="Synthetic-second!"});db.Save();string file=Path.Combine(Paths.Root,"Лицензия.txt");File.WriteAllText(file,"Учебная лицензия");db.AddAttachment(entry.Id,file);db.Save();
   var edited=entry.Copy();try{using(var d=new EntryDialog(edited,app,false,db.Otp,db.Entries,db.AccountGroups()))Capture(d,"118-account-groups-tags");}finally{edited.ClearSecrets();}
   using(var d=new AccountGroupsDialog(db,()=>{db.Save();return true;}))Capture(d,"118-groups");
   using(var d=new GroupEditDialog(db.AccountGroups(),null,group))Capture(d,"118-group-edit");
   using(var d=new AttachmentsDialog(db,entry.Id,()=>{db.Save();return true;}))Capture(d,"118-attachments");
   using(var d=new FieldReferenceDialog(entry,db.Entries))Capture(d,"118-field-references");
   var copy=entry.Copy();try{using(var d=new ApplicationAutoTypeDialog(copy))Capture(d,"118-autotype");}finally{copy.ClearSecrets();}
   using(var d=new AutoTypeHotkeyDialog(Keys.Control|Keys.Alt|Keys.A))Capture(d,"118-hotkey");
   using(var d=new SystemPasskeySetupDialog())Capture(d,"118-system-passkeys");
   using(var d=new MergePasswordDialog())Capture(d,"118-merge-password");
   var merge=new DatabaseMerge{SameDatabase=true,Added=2,Removed=1};merge.Conflicts.Add(new MergeConflict{Name="Учебный аккаунт",Id=entry.Id,LocalTime=DateTime.UtcNow,OtherTime=DateTime.UtcNow.AddMinutes(5)});merge.Conflicts.Add(new MergeConflict{Name="Второй аккаунт",LocalTime=DateTime.UtcNow,OtherTime=DateTime.UtcNow.AddMinutes(5),OtherDeleted=true});using(var d=new MergePreviewDialog(merge))Capture(d,"118-merge-preview");
   using(var d=new FileCredentialDialog("repair",@"C:\Projects\Учебное хранилище"))Capture(d,"118-vault-repair");
   using(var d=new FileHealthDialog("Хранилище: C:\\Projects\\Учебное хранилище\r\nИсправных объектов: 12; предупреждений: 0; критических ошибок: 0\r\nВыполнено исправлений: 1\r\nИсходное хранилище сохранено. Проверьте нужные файлы в копии.",true))Capture(d,"118-repair-report");
   using(var form=new MainForm(app)){typeof(MainForm).GetField("vault",Private).SetValue(form,db);typeof(MainForm).GetMethod("ShowOpen",Private).Invoke(form,null);form.Size=new Size(1080,820);Capture(form,"118-passwords",()=>{form.Text="WinUp";Children(form).OfType<TabControl>().First().SelectedIndex=0;((TextBox)typeof(MainForm).GetField("pwLog",Private).GetValue(form)).Clear();});}
  }finally{db.Lock();}}
 }
}

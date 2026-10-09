using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace WinUp {
 internal static class HostNativeReview {
  static readonly BindingFlags Private=BindingFlags.Instance|BindingFlags.NonPublic;
  [STAThread]static int Main(string[] args){
   if(!Paths.Root.StartsWith(@"C:\WinUp\test\advanced-1.18\host-native-review\",StringComparison.OrdinalIgnoreCase))throw new Exception("Dedicated test folder required");
   if(args.Length==1&&args[0]=="--preflight"){SystemPasskeySetup.Prepare();File.WriteAllText(Path.Combine(Paths.Root,"preflight.txt"),"PASS signed native package and public certificate validated; helper extracted. No certificate trust or Windows registration performed.");return 0;}
   if(args.Length==1&&args[0]=="--system-passkey-trust"){SystemPasskeySetup.TrustCertificate();return 0;}
   if(args.Length!=1||args[0]!="--review")return 2;
   AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib"?CoreLoader.Resolve():EmbeddedModules.Resolve(e.Name);
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
   var bytes=new byte[32];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(bytes);string password=Convert.ToBase64String(bytes);Array.Clear(bytes,0,bytes.Length);
   var app=new AppStore();app.Settings.WizardDone=true;app.Settings.HideFromCapture=false;app.Settings.AutoLockMinutes=1440;app.Settings.AutoTypeHotkey=0;app.Settings.BackupDir=Path.Combine(Paths.Root,"backup");app.Save();WindowsHello.Disable();
   using(var form=new MainForm(app,false))using(var timer=new Timer{Interval=100}){
    var database=KdbxStore.Create(password,null);typeof(MainForm).GetField("vault",Private).SetValue(form,database);typeof(MainForm).GetMethod("ShowOpen",Private).Invoke(form,null);
    form.Text="WinUp — учебная проверка системного провайдера";
    form.Shown+=(s,e)=>{using(var dialog=new SystemPasskeySetupDialog())dialog.ShowDialog(form);};
    var seen=new System.Collections.Generic.HashSet<Form>();
    int previousCount=-1;timer.Tick+=(s,e)=>{int keyCount=database.IsLocked?0:database.Entries.Count(x=>x.Kind=="passkey");if(keyCount!=previousCount){previousCount=keyCount;File.WriteAllText(Path.Combine(Paths.Root,"credential-count.txt"),keyCount.ToString());}foreach(var dialog in Application.OpenForms.Cast<Form>().ToArray()){
     if(seen.Contains(dialog))continue;
     if(dialog is PasskeyConsentDialog&&Children(dialog).OfType<Label>().Any(l=>l.Text=="http://localhost:9335"||l.Text=="https://localhost:9335")){seen.Add(dialog);((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();}
     else if(dialog is PasswordPrompt&&dialog.Text=="WinUp: ключ доступа для localhost"){seen.Add(dialog);((TextBox)typeof(PasswordPrompt).GetField("box",Private).GetValue(dialog)).Text=password;((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();}
    }};
    timer.Start();try{Application.Run(form);}finally{timer.Stop();database.Lock();Secure.Wipe(password);}
   }return 0;
  }
  static System.Collections.Generic.IEnumerable<Control> Children(Control parent){foreach(Control child in parent.Controls){yield return child;foreach(var nested in Children(child))yield return nested;}}
 }
}

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Engine=WinUp.PasskeyEngine.Keys;

namespace WinUp {
    partial class MainForm {
        readonly object systemPasskeySync=new object();readonly Dictionary<Guid,DateTime> systemUsed=new Dictionary<Guid,DateTime>();readonly HashSet<Guid> systemCancelled=new HashSet<Guid>();bool systemPasskeyBusy;
        internal void CancelSystemPasskey(Dictionary<string,object> message){Guid id;if(message.ContainsKey("transaction")&&Guid.TryParse(message["transaction"] as string,out id))lock(systemPasskeySync)systemCancelled.Add(id);}
        static object[] NativeArray(Dictionary<string,object> data,string name){object value;return data.TryGetValue(name,out value)&&value is IEnumerable?((IEnumerable)value).Cast<object>().ToArray():new object[0];}
        bool SystemCancelled(Guid id){lock(systemPasskeySync)return systemCancelled.Contains(id);}
        internal string SystemPasskeyRequest(Dictionary<string,object> message){
            string action=PString(message,"action");var js=new JavaScriptSerializer();if(action=="system_status")return js.Serialize(new{ready=vault!=null&&!vault.IsLocked});if(action!="system_passkey")return "{\"ok\":false}";
            Guid transaction;if(!Guid.TryParse(PString(message,"transaction"),out transaction)||systemPasskeyBusy)return "{\"ok\":false}";lock(systemPasskeySync){foreach(var old in systemUsed.Where(p=>DateTime.UtcNow-p.Value>TimeSpan.FromMinutes(10)).Select(p=>p.Key).ToArray()){systemUsed.Remove(old);systemCancelled.Remove(old);}if(systemUsed.ContainsKey(transaction)||systemCancelled.Contains(transaction))return "{\"ok\":false}";systemUsed.Add(transaction,DateTime.UtcNow);}
            systemPasskeyBusy=true;try{
                var current=vault;if(current==null||current.IsLocked){PwLog("Откройте базу WinUp перед созданием ключа или входом через Windows.");return "{\"ok\":false}";}
                string rp=PString(message,"rp");if(!PasskeyPolicy.ValidRp(rp,rp))return "{\"ok\":false}";bool create=message.ContainsKey("create")&&message["create"] is bool&&(bool)message["create"];
                byte[] hash=WinUpPluginAuthenticator.Decode(PString(message,"hash"),32);if(hash.Length!=32)return "{\"ok\":false}";
                string[] ids=NativeArray(message,"ids").Select(v=>v as string).Where(v=>v!=null).ToArray();var candidates=current.Entries.Where(e=>e.Kind=="passkey"&&e.Target.Equals(rp,StringComparison.OrdinalIgnoreCase)).ToList();
                int algorithm=0;byte[] userId=null;if(create){userId=WinUpPluginAuthenticator.Decode(PString(message,"userId"),64);if(userId.Length==0||candidates.Any(e=>ids.Contains(e.Args)))return "{\"ok\":false}";foreach(var alg in NativeArray(message,"algorithms")){int value=Convert.ToInt32(alg);if(new[]{-7,-8,-257}.Contains(value)){algorithm=value;break;}}if(algorithm==0)return "{\"ok\":false}";}
                else{if(ids.Length>0)candidates=candidates.Where(e=>ids.Contains(e.Args)).ToList();if(candidates.Count==0){PwLog("Для "+rp+" не найден подходящий ключ WinUp.");return "{\"ok\":false}";}}
                LoginEntry selected=null;using(var prompt=new SystemPasskeyConsentDialog(rp,create?PString(message,"user"):null,candidates))using(var timer=new System.Windows.Forms.Timer{Interval=100}){
                    timer.Tick+=(s,e)=>{if(SystemCancelled(transaction)||vault!=current)prompt.Close();};timer.Start();Win.Focus(Handle);if(prompt.ShowDialog(this)!=DialogResult.OK||SystemCancelled(transaction)||vault!=current)return "{\"ok\":false}";if(!create)selected=prompt.Selected;
                }
                if(!VerifyBrowserUser("WinUp: ключ доступа для "+rp)||SystemCancelled(transaction)||vault!=current)return "{\"ok\":false}";
                if(create){string pem;byte[] cose,spki;Engine.Generate(algorithm,out pem,out cose,out spki);try{var id=new byte[32];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(id);var entry=new LoginEntry{Name=rp+" — "+PString(message,"user"),Kind="passkey",Target=rp,Login=PString(message,"user"),Args=PasskeyPolicy.Encode(id),Window=PasskeyPolicy.Encode(userId),Password=pem};if(SystemCancelled(transaction)||vault!=current)return "{\"ok\":false}";current.Entries.Add(entry);if(!SaveBrowserVault()){current.Entries.Remove(entry);entry.ClearSecrets();return "{\"ok\":false}";}return js.Serialize(new{ok=true,id=entry.Args,auth=PasskeyPolicy.Encode(Engine.RegisterData(rp,id,cose))});}finally{Secure.Wipe(pem);}}
                if(selected==null||!current.Entries.Contains(selected))return "{\"ok\":false}";var authData=Engine.AssertionData(rp,selected.PasskeyBackupEligible,selected.PasskeyBackedUp);var signed=authData.Concat(hash).ToArray();var signature=selected.UsePassword(p=>Engine.Sign(p,signed));if(SystemCancelled(transaction)||vault!=current)return "{\"ok\":false}";return js.Serialize(new{ok=true,id=selected.Args,auth=PasskeyPolicy.Encode(authData),signature=PasskeyPolicy.Encode(signature),userId=selected.Window});
            }catch(Exception ex){PwLog("Ключи доступа Windows: "+ex.Message);return "{\"ok\":false}";}finally{systemPasskeyBusy=false;}
        }
    }
    sealed class SystemPasskeyConsentDialog:Dlg,ILockableDialog {
        readonly ComboBox accounts=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList};internal LoginEntry Selected{get{return accounts.SelectedItem as LoginEntry;}}
        internal SystemPasskeyConsentDialog(string rp,string user,List<LoginEntry> entries):base(user==null?"Войти ключом WinUp":"Сохранить ключ в WinUp"){
            Row("Сайт / приложение:",new Label{Text=rp,AutoSize=true});if(user!=null)Row("Аккаунт:",new Label{Text=user,AutoSize=true});else{accounts.DisplayMember="Login";foreach(var e in entries)accounts.Items.Add(e);accounts.SelectedIndex=0;Row("Аккаунт:",accounts);}Note("Запрос получен от Windows. Ключ хранится в открытой базе WinUp. После подтверждения понадобится Windows Hello или пароль базы.");Buttons();Ok.Text=user==null?"Войти":"Создать";
        }
    }
}

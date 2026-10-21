using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Web.Script.Serialization;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Serialization;
namespace WinUp {
    static class CardStorageProbe {
        static readonly List<object> checks=new List<object>();
        static void Check(string name,bool ok){checks.Add(new{name=name,passed=ok});if(!ok)throw new Exception(name);}
        [STAThread]static void Main(){
            try{AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib"?CoreLoader.Resolve():EmbeddedModules.Resolve(e.Name);Run();}
            catch(Exception ex){checks.Add(new{name="Exception",passed=false,error=ex.ToString()});}
            File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"card-storage-results.json"),new JavaScriptSerializer().Serialize(checks));
        }
        [MethodImpl(MethodImplOptions.NoInlining)]static void Run(){
            if(!Path.GetFileName(Paths.Root).StartsWith("storage-qa-",StringComparison.Ordinal)||KdbxStore.Exists)throw new IOException("Fresh synthetic fixture required.");
            const string pw="Cards-Fixture-Only!2026";var store=KdbxStore.Create(pw,null);
            var card=new BankCard{Name="Учебная карта",Holder="TEST OWNER",Number="4111111111111111",Cvv="923",Month=12,Year=2098,Notes="SYNTHETIC-CARD-NOTE"};card.Validate();store.Cards.Add(card);string recovery=store.MakeRecoveryCode();store.Save();string id=card.Id;
            Check("Card UUID assigned and separated from passwords",id.Length==32&&store.Entries.Count==0&&store.Cards.Count==1);
            Check("Masked card shows four digits",card.LastFour=="1111"&&card.Brand=="Visa"&&card.Expiry=="12/98"&&!card.Expired);
            var key=new CompositeKey();key.AddUserKey(new KcpPassword(pw));var independent=new PwDatabase();independent.Open(IOConnectionInfo.FromPath(Paths.KdbxFile),key,null);
            var record=independent.RootGroup.GetEntries(true).Single(e=>e.Strings.ReadSafe("WinUp.Kind")=="card");
            Check("KeePass reads card fields and protected PAN/CVV",record.Strings.ReadSafe("WinUp.CardNumber")=="4111111111111111"&&record.Strings.Get("WinUp.CardNumber").IsProtected&&record.Strings.Get("WinUp.CardCvv").IsProtected&&record.Strings.ReadSafe("WinUp.CardCvv")=="923");independent.Close();
            Check("PAN and card note absent from encrypted file bytes",!Encoding.UTF8.GetString(File.ReadAllBytes(Paths.KdbxFile)).Contains("4111111111111111")&&!Encoding.UTF8.GetString(File.ReadAllBytes(Paths.KdbxFile)).Contains("SYNTHETIC-CARD-NOTE"));
            card.Cvv="234";store.Save();store.Lock();Check("Lock clears retained PAN and CVV",card.UseNumber(n=>n==null)&&card.UseCvv(c=>c==null)&&store.Cards.Count==0);
            int left;StoreResult result;store=KdbxStore.Open(pw,null,out left,out result);Check("Cards reopen with updated secret",result==StoreResult.Ok&&store.Cards.Count==1&&store.Cards[0].UseCvv(c=>c=="234"));
            var csv=Export.Csv(store.Entries,store.Otp);Check("Password CSV excludes card data",!Encoding.UTF8.GetString(csv).Contains("4111111111111111")&&!Encoding.UTF8.GetString(csv).Contains("Учебная карта"));Array.Clear(csv,0,csv.Length);
            card=store.Cards[0];store.Cards.Remove(card);store.Save();Check("Deleting card moves it to trash",store.Cards.Count==0&&store.DeletedRecords().Any(r=>r.Id==id&&r.Kind=="card"));card.Clear();
            store.RestoreDeleted(id);store.Save();Check("Restored card stays a card",store.Cards.Count==1&&store.Cards[0].Id==id&&store.Entries.Count==0);
            store.Lock();var restored=KdbxStore.OpenByRecovery(recovery,out left,out result);Check("Recovery copy includes bank cards",result==StoreResult.Ok&&restored.Cards.Count==1&&restored.Cards[0].UseNumber(n=>n=="4111111111111111"));restored.Lock();
            independent=new PwDatabase();independent.Open(IOConnectionInfo.FromPath(Paths.KdbxFile),key,null);record=independent.RootGroup.GetEntries(true).Single(e=>e.Strings.ReadSafe("WinUp.Kind")=="card");record.Strings.Set("WinUp.CardMonth",new KeePassLib.Security.ProtectedString(false,"invalid"));independent.Save(null);independent.Close();
            store=KdbxStore.Open(pw,null,out left,out result);Check("Malformed imported card does not block opening vault",result==StoreResult.Ok&&store.Cards.Count==1&&store.Cards[0].NeedsReview&&store.Cards[0].Expired);store.Save();store.Lock();
            independent=new PwDatabase();independent.Open(IOConnectionInfo.FromPath(Paths.KdbxFile),key,null);record=independent.RootGroup.GetEntries(true).Single(e=>e.Strings.ReadSafe("WinUp.Kind")=="card");Check("Saving other data preserves malformed card without rewriting secrets",record.Strings.ReadSafe("WinUp.CardMonth")=="invalid"&&record.Strings.ReadSafe("WinUp.CardNumber")=="4111111111111111");independent.Close();
            store=KdbxStore.Open(pw,null,out left,out result);card=store.Cards[0];var fixedCard=new BankCard{Id=card.Id,Name=card.Name,Holder=card.Holder,Month=12,Year=2098,Number="4111111111111111",Cvv="234"};store.Cards[0]=fixedCard;store.Save();card.Clear();store.Lock();store=KdbxStore.Open(pw,null,out left,out result);Check("Reviewing malformed card restores valid autofill eligibility",store.Cards.Count==1&&!store.Cards[0].NeedsReview&&!store.Cards[0].Expired);store.Lock();
            foreach(var number in new[]{"4111111111111112","0000000000000000","4111111111111111<script>","４１１１１１１１１１１１１１１１"}){bool rejected=false;try{BankCard.NormalizeNumber(number);}catch(IOException){rejected=true;}Check("Reject invalid PAN "+checks.Count,rejected);}
            Check("Common formatting is normalized",BankCard.NormalizeNumber("4111-1111 1111 1111")=="4111111111111111");
            foreach(var cvv in new[]{"12","12345","12a"}){bool rejected=false;try{var bad=new BankCard{Name="Invalid",Number="4111111111111111",Cvv=cvv,Month=1,Year=2098};try{bad.Validate();}finally{bad.Clear();}}catch(IOException){rejected=true;}Check("Reject invalid CVV "+checks.Count,rejected);}
            Check("HTTP, credential URLs and spoofed schemes are blocked",BrowserServer.CardOrigin("http://pay.example")==null&&BrowserServer.CardOrigin("https://user:pw@pay.example")==null&&BrowserServer.CardOrigin("javascript:alert(1)")==null&&BrowserServer.CardOrigin("https://PAY.example:8443/pay")=="https://pay.example:8443");
        }
    }
}

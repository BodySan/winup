using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KeePassLib;
using KeePassLib.Security;

namespace WinUp {
    public sealed class BankCard {
        public string Id, Name, Holder;
        public int Month, Year;
        internal bool NeedsReview;
        readonly SecretText number=new SecretText(),cvv=new SecretText(),notes=new SecretText();
        public string Number {set{number.Set(value);}}
        public string Cvv {set{cvv.Set(value);}}
        public string Notes {set{notes.Set(value);}}
        internal T UseNumber<T>(Func<string,T> action){return number.Use(action);}
        internal T UseCvv<T>(Func<string,T> action){return cvv.Use(action);}
        internal T UseNotes<T>(Func<string,T> action){return notes.Use(action);}
        internal string LastFour {get{return number.Use(s=>s==null?"":s.Substring(Math.Max(0,s.Length-4)));}}
        internal string Brand {get{return number.Use(s=>string.IsNullOrEmpty(s)?"Карта":s.StartsWith("4")?"Visa":s.StartsWith("34")||s.StartsWith("37")?"American Express":(s.StartsWith("2200")||s.StartsWith("2201")||s.StartsWith("2202")||s.StartsWith("2203")||s.StartsWith("2204"))?"Мир":s.StartsWith("5")||s.StartsWith("2")?"Mastercard":"Карта");}}
        internal bool Expired {get{return NeedsReview||Year<2000||Year>2199||Month<1||Month>12||new DateTime(Year,Month,1).AddMonths(1)<=DateTime.Today;}}
        internal string Expiry {get{return Month<1||Month>12||Year<2000||Year>2199?"Не указан":Month.ToString("D2")+"/"+(Year%100).ToString("D2");}}
        internal void Clear(){number.Clear();cvv.Clear();notes.Clear();}
        internal static string NormalizeNumber(string value){
            if(value==null||value.Length>64||value.Any(c=>!(c>='0'&&c<='9')&&c!=' '&&c!='-'))throw new IOException("В номере карты допустимы только цифры, пробелы и дефисы.");
            string n=value.Replace(" ","").Replace("-","");if(n.Length<12||n.Length>19)throw new IOException("Номер карты должен содержать от 12 до 19 цифр.");
            int sum=0;bool twice=false;for(int i=n.Length-1;i>=0;i--){int digit=n[i]-'0';if(twice){digit*=2;if(digit>9)digit-=9;}sum+=digit;twice=!twice;}
            if(sum%10!=0||n.All(c=>c=='0'))throw new IOException("Проверьте номер карты: контрольная сумма не совпала.");return n;
        }
        internal void Validate(){
            if(string.IsNullOrWhiteSpace(Name)||Name.Length>120||Name.Any(char.IsControl))throw new IOException("Укажите название карты без переносов строк (до 120 символов).");
            if((Holder??"").Length>120||(Holder??"").Any(char.IsControl)||Month<1||Month>12||Year<2000||Year>2199)throw new IOException("Проверьте имя держателя и срок действия карты.");
            UseNumber(n=>{NormalizeNumber(n);return 0;});UseCvv(c=>{if(!string.IsNullOrEmpty(c)&&(c.Length!=3&&c.Length!=4||c.Any(x=>x<'0'||x>'9')))throw new IOException("CVV/CVC должен содержать 3 или 4 цифры.");return 0;});
            UseNotes(n=>{if((n??"").Length>16000)throw new IOException("Слишком длинная заметка.");return 0;});
        }
    }
    public sealed partial class KdbxStore {
        public readonly List<BankCard> Cards=new List<BankCard>();
        PwGroup CardGroup(bool create){
            var group=db.RootGroup.Groups.FirstOrDefault(g=>g.CustomData.Get("WinUp.Cards")=="1");
            if(group==null&&create){group=new PwGroup(true,true,"Банковские карты",PwIcon.Money);group.CustomData.Set("WinUp.Cards","1");db.RootGroup.AddGroup(group,true);}return group;
        }
        IEnumerable<PwEntry> CardRecords(){return WalkGroups(db.RootGroup).Where(g=>!Under(g,Trash(false))).SelectMany(g=>g.Entries).Where(e=>GetStr(e,"WinUp.Kind")=="card");}
        void ClearCards(){foreach(var card in Cards)card.Clear();Cards.Clear();}
        void LoadCards(){
            ClearCards();foreach(var entry in CardRecords()){
                int month,year;int.TryParse(GetStr(entry,"WinUp.CardMonth"),out month);int.TryParse(GetStr(entry,"WinUp.CardYear"),out year);
                var card=new BankCard{Id=entry.Uuid.ToHexString(),Name=entry.Strings.ReadSafe(PwDefs.TitleField),Holder=entry.Strings.ReadSafe(PwDefs.UserNameField),Month=month,Year=year};
                string number=ReadSecret(entry,"WinUp.CardNumber"),cvv=ReadSecret(entry,"WinUp.CardCvv"),notes=ReadSecret(entry,PwDefs.NotesField);
                try{card.Number=number;card.Cvv=cvv;card.Notes=notes;try{card.Validate();}catch(IOException){card.NeedsReview=true;}Cards.Add(card);}finally{Secure.Wipe(number);Secure.Wipe(cvv);Secure.Wipe(notes);}
            }
        }
        static void FillCard(PwEntry entry,BankCard card){
            SetStr(entry,"WinUp.Kind","card");entry.Strings.Set(PwDefs.TitleField,new ProtectedString(false,card.Name));entry.Strings.Set(PwDefs.UserNameField,ProtectedUtf8(card.Holder??""));
            SetStr(entry,"WinUp.CardMonth",card.Month.ToString());SetStr(entry,"WinUp.CardYear",card.Year.ToString());
            card.UseNumber(n=>{entry.Strings.Set("WinUp.CardNumber",ProtectedUtf8(n));return 0;});card.UseCvv(c=>{entry.Strings.Set("WinUp.CardCvv",ProtectedUtf8(c??""));return 0;});card.UseNotes(n=>{entry.Strings.Set(PwDefs.NotesField,ProtectedUtf8(n??""));return 0;});
        }
        void SyncCards(){
            var existing=CardRecords().ToDictionary(e=>e.Uuid.ToHexString());var keep=new HashSet<string>();
            foreach(var card in Cards){PwEntry entry;bool found=card.Id!=null&&existing.TryGetValue(card.Id,out entry);if(found&&card.NeedsReview){keep.Add(card.Id);continue;}card.Validate();if(!found){entry=new PwEntry(true,true);card.Id=entry.Uuid.ToHexString();CardGroup(true).AddEntry(entry,true);}else entry=existing[card.Id];UpdateWithHistory(entry,e=>FillCard(e,card),found);keep.Add(card.Id);}
            foreach(var pair in existing)if(!keep.Contains(pair.Key))MoveToTrash(pair.Value,false);
        }
    }
}

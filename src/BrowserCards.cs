using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp {
    partial class BrowserServer {
        internal static string CardOrigin(string value){Uri uri;if(!Uri.TryCreate(value,UriKind.Absolute,out uri)||uri.Scheme!="https"||uri.UserInfo.Length!=0||string.IsNullOrEmpty(uri.IdnHost))return null;return SiteDomain.OriginOf(value);}
        string CardRequest(string token,string type,Dictionary<string,object> request){
            string response=null;object value;
            string url=request.TryGetValue("url",out value)?value as string:null;
            string origin=CardOrigin(url),id=request.TryGetValue("id",out value)?value as string:null;
            var origins=new List<string>();
            if(type=="card-fill"){
                var values=request.TryGetValue("origins",out value)?value as IEnumerable:null;
                if(origin==null||id==null||values==null||value is string)return Err("insecure");
                foreach(var item in values){string target=CardOrigin(item as string);if(target==null||origins.Count>=12)return Err("bad_request");if(!origins.Contains(target))origins.Add(target);}
                if(origins.Count==0)return Err("bad_request");
            }
            if(!RunUi(delegate {
                var active=owner.VaultNow;if(active==null){response=Err("locked");return;}
                if(!BrowserPair.IsPaired(token)){response=Err("not_paired");return;}
                var json=new JavaScriptSerializer();
                if(type=="card-list"){response=json.Serialize(new{ok=true,items=active.Cards.Take(200).Select(c=>new{id=c.Id,name=c.Name,lastFour=c.LastFour,brand=c.Brand,expiry=c.Expiry,expired=c.Expired,invalid=c.NeedsReview}).ToArray()});return;}
                var card=active.Cards.FirstOrDefault(c=>c.Id==id);if(card==null){response=Err("not_found");return;}if(card.Expired){response=Err("card_expired");return;}
                if(askOpen){response=Err("busy");return;}askOpen=true;
                try {
                    Win.Focus(owner.Handle);
                    string receivers=string.Join("\n",origins.Select(s=>"• "+s));
                    if(MessageBox.Show(owner,"Заполнить карту «"+card.Name+"» (•••• "+card.LastFour+")?\n\nСайт: "+origin+"\nПолучатели данных формы:\n"+receivers+"\n\nБудут переданы номер, срок действия, держатель и сохранённый CVV/CVC. Оплата автоматически не выполняется.","WinUp — заполнение карты",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes){response=Err("denied");return;}
                }finally{askOpen=false;}
                if(owner.VaultNow!=active||active.IsLocked){response=Err("locked");return;}if(!BrowserPair.IsPaired(token)){response=Err("not_paired");return;}if(!active.Cards.Contains(card)){response=Err("not_found");return;}if(card.Expired){response=Err("card_expired");return;}
                response=card.UseNumber(number=>card.UseCvv(cvv=>json.Serialize(new{ok=true,generation=owner.BrowserGeneration,number=number,cvv=cvv??"",holder=card.Holder??"",month=card.Month,year=card.Year,brand=card.Brand})));
            }))return Err("host_error");return response??Err("host_error");
        }
    }
}

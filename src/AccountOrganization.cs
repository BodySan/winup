using System;
using System.Collections.Generic;
using System.Linq;

namespace WinUp {
    internal static class AccountOrganization {
        internal static readonly string[] Categories={"Игры","Дом","Еда","Покупки","Поездки и транспорт","Финансы","Работа и разработка","Учёба","Почта и облако","Общение","Видео и музыка","Нейросети","Связь и интернет","Госуслуги","Другое"};
        internal static string Category(LoginTemplate template){return string.IsNullOrWhiteSpace(template.Category)?"Другое":template.Category.Trim();}
        internal static string Category(LoginEntry entry,IEnumerable<LoginTemplate> templates){
            if(!string.IsNullOrWhiteSpace(entry.Category))return entry.Category.Trim();
            var match=templates.FirstOrDefault(t=>SameService(entry,t.Name,t.Target,t.LoginProfile,t.LoginUrl));
            return match==null?"Другое":Category(match);
        }
        internal static bool SameService(LoginEntry entry,string name,string address,string profile,string loginAddress=null){
            if(string.Equals(AppStore.TemplateName(entry.Name),AppStore.TemplateName(name),StringComparison.CurrentCultureIgnoreCase))return true;
            if(!string.IsNullOrEmpty(profile)&&profile!="generic"&&profile==entry.LoginProfile)return true;
            Uri left,right;
            string entryAddress=entry.Kind=="passkey"?"https://"+entry.Target:entry.Target;
            if(!Uri.TryCreate(entryAddress,UriKind.Absolute,out left)||(left.Scheme!="http"&&left.Scheme!="https"))return false;
            foreach(string candidate in new[]{address,loginAddress})if(Uri.TryCreate(candidate,UriKind.Absolute,out right)&&(right.Scheme=="http"||right.Scheme=="https")&&
                (left.Host.Equals(right.Host,StringComparison.OrdinalIgnoreCase)||(entry.Kind=="passkey"&&right.Host.EndsWith("."+left.Host,StringComparison.OrdinalIgnoreCase))))return true;
            return false;
        }
        internal static string DisplayLogin(LoginEntry entry,bool secondary=false){
            try{return (secondary?entry.ResolvedLogin2:entry.ResolvedLogin)??"";}
            catch(System.IO.IOException){return "Связанный логин недоступен";}
        }
        internal static bool HasLogin(LoginEntry entry,string login){
            try{if(entry.ResolvedLogin==login)return true;}catch(System.IO.IOException){}
            try{return entry.ResolvedLogin2==login;}catch(System.IO.IOException){return false;}
        }
        internal static IEnumerable<LoginEntry> Filter(IEnumerable<LoginEntry> entries,IEnumerable<LoginTemplate> templates,string search,string category,int kind,bool pinnedOnly){
            string query=(search??"").Trim();
            return entries.Where(e=>e.Kind!="passkey"&&(!pinnedOnly||e.Pinned)&&
                (kind==0||e.Kind==(kind==1?"site":kind==2?"app":"both"))&&
                (string.IsNullOrEmpty(category)||Category(e,templates).Equals(category,StringComparison.CurrentCultureIgnoreCase))&&
                new[]{e.Name,e.Login,e.Login2,DisplayLogin(e),DisplayLogin(e,true),e.Target,Category(e,templates)}.Concat(e.Tags).Any(value=>(value??"").IndexOf(query,StringComparison.CurrentCultureIgnoreCase)>=0))
                .OrderByDescending(e=>e.Pinned).ThenBy(e=>e.Name,StringComparer.CurrentCultureIgnoreCase);
        }
    }
}

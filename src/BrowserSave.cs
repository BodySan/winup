using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp {
    partial class MainForm {
        internal static List<LoginEntry> BrowserSaveMatches(KdbxStore current,string url,string login) {
            string host=SiteDomain.HostOf(url);
            return current.Entries.Where(e => (e.Kind == "site" || e.Kind == "both") &&
                (SiteDomain.SameHost(SiteDomain.HostOf(e.Target),host) || LoginProfiles.MatchesLoginOrigin(e,url)) && (e.Login == login || e.Login2 == login))
                .OrderByDescending(e=>SiteDomain.SameHost(SiteDomain.HostOf(e.Target),host)).ThenBy(e=>e.Name).ToList();
        }
        internal string BrowserSave(string url, string login, string password, Func<bool> authorized) {
            string host; var origin = PasskeyPolicy.Origin(url, out host);
            if(origin == null) return SaveReply(false,"insecure");
            var current = vault;
            if(current == null) return SaveReply(false,"locked");
            var matches=BrowserSaveMatches(current,url,login);
            var old=matches.Count==1 ? matches[0] : null;
            if(matches.Count>1) {
                using(var choice=new BrowserSaveChoiceDialog(origin,matches)) {
                    Win.Focus(Handle);
                    if(choice.ShowDialog(this)!=DialogResult.OK) return SaveReply(false,"denied");
                    if(vault!=current || !authorized()) return SaveReply(false,"locked");
                    old=choice.Selected;
                    if(old==null || !current.Entries.Contains(old)) return SaveReply(false,"not_found");
                }
            }
            var copy = old == null ? new LoginEntry { Id=AppStore.NewId(),Name=host,Target=origin,Login=login } : old.Copy();
            copy.Password=password;
            bool retained=false;
            try {
                using(var dialog = new EntryDialog(copy,store,false,current.Otp,current.Entries)) {
                    dialog.Text=(old == null ? "Сохранить пароль — " : "Обновить пароль — ")+origin;
                    Win.Focus(Handle);
                    if(dialog.ShowDialog(this) != DialogResult.OK) return SaveReply(false,"denied");
                    if(vault != current || !authorized()) return SaveReply(false,"locked");
                    if(copy.Kind == "app" || !(SiteDomain.SameHost(SiteDomain.HostOf(copy.Target),host) || LoginProfiles.MatchesLoginOrigin(copy,url))) return SaveReply(false,"page_changed");
                    if(old != null && !current.Entries.Contains(old)) return SaveReply(false,"not_found");
                    int index = old == null ? -1 : current.Entries.IndexOf(old);
                    if(index < 0) current.Entries.Add(copy); else current.Entries[index]=copy;
                    current.Otp.AddRange(dialog.NewOtp);
                    if(!SaveBrowserVault()) {
                        if(index < 0) current.Entries.Remove(copy); else current.Entries[index]=old;
                        foreach(var otp in dialog.NewOtp) { current.Otp.Remove(otp); otp.ClearSecret(); }
                        return SaveReply(false,"save_failed");
                    }
                    retained=true; if(old != null) old.ClearSecrets(); RefreshEntries(); RefreshOtp();
                    PwLog("Расширение: "+(old == null ? "сохранена" : "обновлена")+" запись для "+host+".");
                    return SaveReply(true,null);
                }
            } finally { if(!retained) copy.ClearSecrets(); }
        }
        static string SaveReply(bool ok,string error) { return new JavaScriptSerializer().Serialize(new { ok=ok,error=error }); }
    }
    sealed class BrowserSaveChoiceDialog : Dlg, ILockableDialog {
        sealed class Item {
            public LoginEntry Entry;
            public override string ToString() {return Entry.Name+" — "+Entry.Target+" — "+Entry.Login;}
        }
        readonly System.Windows.Forms.ListBox choices=new System.Windows.Forms.ListBox {Height=180,IntegralHeight=false,HorizontalScrollbar=true};
        public LoginEntry Selected {get {var item=choices.SelectedItem as Item;return item==null ? null : item.Entry;}}
        public BrowserSaveChoiceDialog(string origin,IEnumerable<LoginEntry> matches) : base("Какую запись обновить?") {
            Note("Для "+origin+" найдено несколько записей с этим логином. Выберите запись, пароль которой нужно обновить.");
            foreach(var entry in matches)choices.Items.Add(new Item {Entry=entry});
            choices.SelectedIndex=-1;Ok.Enabled=false;
            choices.SelectedIndexChanged+=(s,e)=>Ok.Enabled=Selected!=null;
            FullRow(choices);Buttons();Ok.Text="Выбрать";
        }
    }
}

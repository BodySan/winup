using System;
using System.Linq;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp {
    partial class MainForm {
        internal string BrowserSave(string url, string login, string password, Func<bool> authorized) {
            string host; var origin = PasskeyPolicy.Origin(url, out host);
            if(origin == null) return SaveReply(false,"insecure");
            var current = vault;
            if(current == null) return SaveReply(false,"locked");
            var old = current.Entries.FirstOrDefault(e => (e.Kind == "site" || e.Kind == "both") &&
                SiteDomain.SameHost(SiteDomain.HostOf(e.Target),host) && (e.Login == login || e.Login2 == login));
            var copy = old == null ? new LoginEntry { Id=AppStore.NewId(),Name=host,Target=origin,Login=login } : old.Copy();
            copy.Password=password;
            bool retained=false;
            try {
                using(var dialog = new EntryDialog(copy,store,false,current.Otp,current.Entries)) {
                    dialog.Text=(old == null ? "Сохранить пароль — " : "Обновить пароль — ")+origin;
                    Win.Focus(Handle);
                    if(dialog.ShowDialog(this) != DialogResult.OK) return SaveReply(false,"denied");
                    if(vault != current || !authorized()) return SaveReply(false,"locked");
                    if(copy.Kind == "app" || !SiteDomain.SameHost(SiteDomain.HostOf(copy.Target),host)) return SaveReply(false,"page_changed");
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
}

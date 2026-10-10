using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

namespace WinUp {
    partial class MainForm {
        internal void RefreshSystemPasskeyCache() {
            if (!SystemPasskeySetup.OwnsRegistration()) return;
            try {
                var labels = new List<SystemPasskeyCredential>();
                if (vault != null && !vault.IsLocked) foreach (var entry in vault.Entries.Where(x => x.Kind == "passkey")) {
                    try {
                        if (!PasskeyPolicy.ValidRp(entry.Target, entry.Target)) continue;
                        PasskeyPolicy.Decode(entry.Args, 1, 1024); PasskeyPolicy.Decode(entry.Window, 1, 64);
                        labels.Add(new SystemPasskeyCredential { Id = entry.Args, Rp = entry.Target, UserId = entry.Window,
                            User = entry.Login ?? "", Display = entry.Name ?? entry.Target });
                    } catch (Exception) { PwLog("Не удалось добавить повреждённый ключ в список Windows: " + entry.Name); }
                }
                SystemPasskeySetup.UpdateCredentialCache(labels);
            } catch (Exception ex) { PwLog("Список ключей Windows не обновлён: " + ex.Message + ". Проверьте подключение WinUp в разделе ключей доступа."); }
        }
    }
}

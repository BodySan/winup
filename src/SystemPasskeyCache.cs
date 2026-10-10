// Credential metadata cache adapted from KeePassPasskey (Uwe Koegel,
// GPL-3.0-or-later). Only public identifiers and account labels reach Windows.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using WinUp.SystemPasskeyNative;

namespace WinUp {
    internal sealed class SystemPasskeyCredential {
        public string Id { get; set; }
        public string Rp { get; set; }
        public string UserId { get; set; }
        public string User { get; set; }
        public string Display { get; set; }
        internal string Identity { get { return Id + "|" + Rp; } }
        internal bool Same(SystemPasskeyCredential other) {
            return Identity == other.Identity && UserId == other.UserId && User == other.User && Display == other.Display;
        }
    }

    internal static unsafe class SystemPasskeyCache {
        static void Check(int result) { if (result < 0) Marshal.ThrowExceptionForHR(result); }
        static string Text(char* value) {
            if (value == null) return "";
            for (int i = 0; i <= 4096; i++) if (value[i] == 0) return new string(value, 0, i);
            throw new IOException("Windows credential label is too long");
        }
        internal static List<SystemPasskeyCredential> Read() {
            uint count = 0;
            WebAuthnPluginCredentialDetails* details = null;
            int result = WebAuthnPluginApi.WebAuthNPluginAuthenticatorGetAllCredentials(ref SystemPasskeyProvider.Clsid, &count, &details);
            try {
                Check(result);
                if (count > 10000 || count != 0 && details == null) throw new IOException("Invalid Windows credential list");
                var values = new List<SystemPasskeyCredential>();
                for (uint i = 0; i < count; i++) {
                    var item = details[i];
                    values.Add(new SystemPasskeyCredential {
                        Id = PasskeyPolicy.Encode(WinUpPluginAuthenticator.Bytes(item.pbCredentialId, item.cbCredentialId, 1024)),
                        Rp = Text(item.pwszRpId),
                        UserId = PasskeyPolicy.Encode(WinUpPluginAuthenticator.Bytes(item.pbUserId, item.cbUserId, 64)),
                        User = Text(item.pwszUserName), Display = Text(item.pwszUserDisplayName)
                    });
                }
                return values;
            } finally { if (details != null) WebAuthnPluginApi.WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(count, details); }
        }
        static void Apply(SystemPasskeyCredential item, bool remove) {
            byte[] credential = PasskeyPolicy.Decode(item.Id, 1, 1024), user = PasskeyPolicy.Decode(item.UserId, 0, 64);
            fixed (byte* credentialPointer = credential) fixed (byte* userPointer = user)
            fixed (char* rp = item.Rp) fixed (char* name = item.User) fixed (char* display = item.Display) {
                var detail = new WebAuthnPluginCredentialDetails {
                    cbCredentialId = (uint)credential.Length, pbCredentialId = credentialPointer,
                    pwszRpId = rp, pwszRpName = rp, cbUserId = (uint)user.Length, pbUserId = userPointer,
                    pwszUserName = name, pwszUserDisplayName = display
                };
                int result = remove
                    ? WebAuthnPluginApi.WebAuthNPluginAuthenticatorRemoveCredentials(ref SystemPasskeyProvider.Clsid, 1, &detail)
                    : WebAuthnPluginApi.WebAuthNPluginAuthenticatorAddCredentials(ref SystemPasskeyProvider.Clsid, 1, &detail);
                if (remove && result == unchecked((int)0x80090011) || !remove && result == unchecked((int)0x8009000F)) return;
                Check(result);
            }
        }
        internal static void Synchronize(IEnumerable<SystemPasskeyCredential> credentials) {
            var desired = credentials.ToList();
            if (desired.Count > 10000) throw new IOException("Too many Windows credential labels");
            foreach (var item in desired) {
                if (item == null || string.IsNullOrEmpty(item.Rp) || item.Rp.Length > 253 || item.Rp.IndexOf('\0') >= 0 ||
                    item.User == null || item.Display == null || item.User.Length > 4096 || item.Display.Length > 4096 ||
                    item.User.IndexOf('\0') >= 0 || item.Display.IndexOf('\0') >= 0) throw new IOException("Invalid credential label");
                PasskeyPolicy.Decode(item.Id, 1, 1024); PasskeyPolicy.Decode(item.UserId, 0, 64);
            }
            desired = desired.GroupBy(x => x.Id, StringComparer.Ordinal).Select(x => x.First()).ToList();
            using (var gate = new Mutex(false, "Local\\WinUp-PasskeyCache-" + SystemPasskeyProvider.Clsid.ToString("N"))) {
                bool acquired = false;
                try {
                    try { acquired = gate.WaitOne(5000); } catch (AbandonedMutexException) { acquired = true; }
                    if (!acquired) throw new IOException("Windows credential list is busy");
                    var unclaimed = Read();
                    var add = new List<SystemPasskeyCredential>();
                    var remove = new List<SystemPasskeyCredential>();
                    foreach (var item in desired) {
                        int match = unclaimed.FindIndex(x => x.Same(item));
                        if (match < 0) match = unclaimed.FindIndex(x => x.Identity == item.Identity);
                        if (match < 0) { add.Add(item); continue; }
                        var previous = unclaimed[match]; unclaimed.RemoveAt(match);
                        if (!previous.Same(item)) { remove.Add(previous); add.Add(item); }
                    }
                    remove.AddRange(unclaimed);
                    foreach (var item in remove) Apply(item, true);
                    foreach (var item in add) Apply(item, false);
                    var actual = Read();
                    if (actual.Count != desired.Count || desired.Any(item => actual.Count(x => x.Same(item)) != 1))
                        throw new IOException("Windows did not retain the requested credential list");
                } finally { if (acquired) gate.ReleaseMutex(); }
            }
        }
    }
}

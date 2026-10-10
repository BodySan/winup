using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KeePassLib;
using KeePassLib.Security;

namespace WinUp {
    internal sealed class RecordVersion {
        internal string Id,Name,Kind;internal int Index;internal DateTime Time;
    }
    public sealed partial class KdbxStore {
        const string TrashKind="WinUp.DeletedKind", TrashLinks="WinUp.DeletedLinks", TrashTime="WinUp.DeletedAt";
        internal static bool IsUserField(string name){return !new[]{"Title","UserName","Password","URL","Notes"}.Contains(name)&&!name.StartsWith("WinUp.",StringComparison.Ordinal)&&!name.StartsWith("KPEX_PASSKEY_",StringComparison.Ordinal)&&!name.StartsWith("TimeOtp-",StringComparison.Ordinal)&&!name.StartsWith("HmacOtp-",StringComparison.Ordinal);}
        internal static void ValidateFieldName(string name){
            if(string.IsNullOrWhiteSpace(name)||name.Length>128||name.Any(char.IsControl)||!IsUserField(name))throw new IOException("Недопустимое имя дополнительного поля: "+name);
        }
        void UpdateWithHistory(PwEntry entry,Action<PwEntry> fill,bool existed){
            var proposed=entry.CloneDeep();fill(proposed);
            if(existed&&entry.EqualsEntry(proposed,PwCompareOptions.IgnoreTimes|PwCompareOptions.IgnoreHistory|PwCompareOptions.IgnoreParentGroup,KeePassLib.MemProtCmpMode.Full))return;
            if(existed)entry.CreateBackup(db);
            fill(entry);entry.Touch(true,false);entry.MaintainBackups(db);
        }
        PwGroup Trash(bool create){
            var group=db.RootGroup.FindGroup(db.RecycleBinUuid,true);
            if(group==null&&create){group=new PwGroup(true,true,"Корзина",PwIcon.TrashBin);db.RootGroup.AddGroup(group,true);db.RecycleBinUuid=group.Uuid;db.RecycleBinEnabled=true;}
            return group;
        }
        void MoveToTrash(PwEntry entry,bool otp){
            if(otp){var links=AccountRecords().Where(p=>GetStr(p,"WinUp.OtpRef")==entry.Uuid.ToHexString()).Select(p=>p.Uuid.ToHexString());SetStr(entry,TrashLinks,string.Join(",",links));}
            SetStr(entry,"WinUp.DeletedGroup",entry.ParentGroup.Uuid.ToHexString());
            SetStr(entry,TrashKind,otp?"otp":"entry");SetStr(entry,TrashTime,DateTime.UtcNow.ToString("o"));
            entry.ParentGroup.Entries.Remove(entry);Trash(true).AddEntry(entry,true);entry.LocationChanged=DateTime.UtcNow;entry.Touch(true,false);
        }
        PwEntry ActiveRecord(string id,bool otp){var group=FindOtpGroup(false);return (otp?(group==null?new PwEntry[0]:group.Entries.ToArray()):AccountRecords()).FirstOrDefault(e=>e.Uuid.ToHexString()==id);}
        internal List<RecordVersion> Versions(string id,bool otp){
            var entry=ActiveRecord(id,otp);var result=new List<RecordVersion>();if(entry==null)return result;
            for(int i=(int)entry.History.UCount-1;i>=0;i--){var item=entry.History.GetAt((uint)i);result.Add(new RecordVersion{Id=id,Index=i,Name=item.Strings.ReadSafe("Title"),Kind=otp?"otp":GetStr(item,"WinUp.Kind"),Time=item.LastModificationTime});}return result;
        }
        internal LoginEntry HistoryEntry(string id,int index){var entry=ActiveRecord(id,false);if(entry==null||index<0||index>=entry.History.UCount)throw new IOException("Версия записи больше не доступна.");return FromEntry(entry.History.GetAt((uint)index));}
        internal OtpEntry HistoryOtp(string id,int index){var entry=ActiveRecord(id,true);if(entry==null||index<0||index>=entry.History.UCount)throw new IOException("Версия 2FA больше не доступна.");return OtpFromEntry(entry.History.GetAt((uint)index));}
        internal void RestoreHistory(string id,int index,bool otp){
            if(saveFailed)throw new IOException("Откройте базу заново.");var entry=ActiveRecord(id,otp);
            if(entry==null||index<0||index>=entry.History.UCount)throw new IOException("Версия больше не доступна.");
            entry.RestoreFromBackup((uint)index,db);entry.Touch(true,false);
            if(!otp){var trash=Trash(false);if(trash!=null)foreach(var refId in new[]{GetStr(entry,"WinUp.OtpRef"),GetStr(entry,"WinUp.PasskeyRef")}.Where(s=>!string.IsNullOrEmpty(s))){var match=trash.Entries.FirstOrDefault(e=>e.Uuid.ToHexString()==refId);if(match!=null)RestoreDeletedCore(match,false);}}
            ReloadRecords();
        }
        internal List<RecordVersion> DeletedRecords(){
            var group=Trash(false);if(group==null)return new List<RecordVersion>();
            return group.Entries.Select(e=>new RecordVersion{Id=e.Uuid.ToHexString(),Name=e.Strings.ReadSafe("Title"),Kind=GetStr(e,TrashKind)=="otp"?"otp":GetStr(e,"WinUp.Kind"),Time=DeletedAt(e)}).OrderByDescending(e=>e.Time).ToList();
        }
        static DateTime DeletedAt(PwEntry entry){DateTime time;return DateTime.TryParse(GetStr(entry,TrashTime),null,System.Globalization.DateTimeStyles.RoundtripKind,out time)?time:entry.LastModificationTime;}
        internal int RestoreDeleted(string id){
            if(saveFailed)throw new IOException("Откройте базу заново.");var group=Trash(false);var entry=group==null?null:group.Entries.FirstOrDefault(e=>e.Uuid.ToHexString()==id);if(entry==null)throw new IOException("Запись в корзине не найдена.");
            int count=RestoreDeletedCore(entry,true);ReloadRecords();return count;
        }
        int RestoreDeletedCore(PwEntry entry,bool related){
            bool otp=GetStr(entry,TrashKind)=="otp";string id=entry.Uuid.ToHexString(),links=GetStr(entry,TrashLinks);int count=1;
            if(ActiveRecord(id,otp)!=null)throw new IOException("Запись с этим идентификатором уже существует.");
            if(related&&!otp){foreach(var refId in new[]{GetStr(entry,"WinUp.OtpRef"),GetStr(entry,"WinUp.PasskeyRef")}.Where(s=>!string.IsNullOrEmpty(s))){var match=Trash(false).Entries.FirstOrDefault(e=>e.Uuid.ToHexString()==refId);if(match!=null)count+=RestoreDeletedCore(match,false);}}
            entry.ParentGroup.Entries.Remove(entry);var group=otp?FindOtpGroup(true):FindAccountGroup(GetStr(entry,"WinUp.DeletedGroup"))??db.RootGroup;group.AddEntry(entry,true);
            entry.Strings.Remove("WinUp.DeletedGroup");
            entry.Strings.Remove(TrashKind);entry.Strings.Remove(TrashTime);entry.Strings.Remove(TrashLinks);entry.LocationChanged=DateTime.UtcNow;entry.Touch(true,false);
            if(otp&&!string.IsNullOrEmpty(links))foreach(var refId in links.Split(',')){var linked=ActiveRecord(refId,false);if(linked!=null&&GetStr(linked,"WinUp.TwoFa")=="ask"&&string.IsNullOrEmpty(GetStr(linked,"WinUp.OtpRef"))){linked.CreateBackup(db);SetStr(linked,"WinUp.TwoFa","link");SetStr(linked,"WinUp.OtpRef",id);linked.Touch(true,false);}}
            return count;
        }
        internal void PurgeDeleted(IEnumerable<string> ids){
            if(saveFailed)throw new IOException("Откройте базу заново.");var group=Trash(false);if(group==null)return;
            foreach(var id in ids){var entry=group.Entries.FirstOrDefault(e=>e.Uuid.ToHexString()==id);if(entry==null)continue;group.Entries.Remove(entry);db.DeletedObjects.Add(new PwDeletedObject(entry.Uuid,DateTime.UtcNow));}
        }
        void ReloadRecords(){foreach(var entry in Entries)entry.ClearSecrets();foreach(var otp in Otp)otp.ClearSecret();LoadFromDb();}
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using KeePassLib;
using KeePassLib.Security;

namespace WinUp {
    internal sealed class AccountGroupInfo {
        internal string Id,ParentId,Name,Path;
        public override string ToString(){return Path;}
    }
    internal sealed class AccountAttachmentInfo {
        internal string Name;internal uint Size;
    }
    internal sealed class MergeConflict {
        internal string Id,Name;internal DateTime LocalTime,OtherTime;
        internal bool LocalDeleted,OtherDeleted;
        internal string Choice="Более новая";
    }
    internal sealed class DatabaseMerge:IDisposable {
        internal PwDatabase Other;internal string LocalStamp;
        internal List<MergeConflict> Conflicts=new List<MergeConflict>();
        internal int Added,Removed;internal bool SameDatabase;
        public void Dispose(){if(Other!=null){Other.Close();Other=null;}}
    }
    public sealed partial class KdbxStore {
        IEnumerable<PwEntry> AccountRecords(){
            var trash=Trash(false);var otp=FindOtpGroup(false);
            return WalkGroups(db.RootGroup).Where(g=>!Under(g,trash)&&!Under(g,otp)).SelectMany(g=>g.Entries);
        }
        static IEnumerable<PwGroup> WalkGroups(PwGroup root){yield return root;foreach(var group in root.Groups)foreach(var child in WalkGroups(group))yield return child;}
        static bool Under(PwGroup group,PwGroup parent){if(parent==null)return false;for(var g=group;g!=null;g=g.ParentGroup)if(g==parent)return true;return false;}
        PwGroup FindAccountGroup(string id){return WalkGroups(db.RootGroup).FirstOrDefault(g=>g.Uuid.ToHexString()==id&&!Under(g,Trash(false))&&!Under(g,FindOtpGroup(false)));}
        PwGroup AccountGroup(string id){if(string.IsNullOrEmpty(id))return db.RootGroup;var group=FindAccountGroup(id);if(group==null)throw new IOException("Группа записи больше не существует. Выберите другую группу.");return group;}
        void Ready(){if(db==null||!db.IsOpen||saveFailed)throw new IOException("Базу нужно открыть заново.");}
        internal bool IsLocked{get{return db==null||!db.IsOpen||saveFailed;}}
        internal long RecordRevision;
        internal List<AccountGroupInfo> AccountGroups(){Ready();return WalkGroups(db.RootGroup).Where(g=>!Under(g,Trash(false))&&!Under(g,FindOtpGroup(false))).Select(g=>new AccountGroupInfo{Id=g.Uuid.ToHexString(),ParentId=g.ParentGroup==null?null:g.ParentGroup.Uuid.ToHexString(),Name=g.Name,Path=GroupPath(g)}).ToList();}
        string GroupPath(PwGroup group){var parts=new List<string>();for(var g=group;g!=null&&g!=db.RootGroup;g=g.ParentGroup)parts.Add(g.Name);parts.Reverse();return parts.Count==0?"Без группы":string.Join(" / ",parts);}
        internal string CreateAccountGroup(string parent,string name){Ready();ValidateGroupName(name);var target=AccountGroup(parent);if(target.Groups.Any(g=>g.Name.Equals(name.Trim(),StringComparison.CurrentCultureIgnoreCase)))throw new IOException("Группа с таким названием уже есть.");var group=new PwGroup(true,true,name.Trim(),PwIcon.Folder);target.AddGroup(group,true);return group.Uuid.ToHexString();}
        internal void ChangeAccountGroup(string id,string parent,string name){Ready();ValidateGroupName(name);var group=AccountGroup(id);if(group==db.RootGroup)throw new IOException("Корневую группу менять нельзя.");var target=AccountGroup(parent);if(Under(target,group))throw new IOException("Нельзя переместить группу внутрь неё самой.");if(target.Groups.Any(g=>g!=group&&g.Name.Equals(name.Trim(),StringComparison.CurrentCultureIgnoreCase)))throw new IOException("Группа с таким названием уже есть.");if(group.ParentGroup!=target){group.ParentGroup.Groups.Remove(group);target.AddGroup(group,true);group.LocationChanged=DateTime.UtcNow;}group.Name=name.Trim();group.Touch(true,false);}
        internal void DeleteAccountGroup(string id){Ready();var group=AccountGroup(id);if(group==db.RootGroup||group.Entries.UCount!=0||group.Groups.UCount!=0)throw new IOException("Удалить можно только пустую группу. Сначала перенесите записи и вложенные группы.");group.ParentGroup.Groups.Remove(group);db.DeletedObjects.Add(new PwDeletedObject(group.Uuid,DateTime.UtcNow));}
        static void ValidateGroupName(string name){if(string.IsNullOrWhiteSpace(name)||name.Trim().Length>128||name.Any(char.IsControl)||name.Contains("/")||name.Contains("\\"))throw new IOException("Название группы должно содержать от 1 до 128 символов, без / и \\.");}
        internal bool InAccountGroup(LoginEntry entry,string id){if(string.IsNullOrEmpty(id))return true;var group=FindAccountGroup(id);return group==db.RootGroup?FindAccountGroup(entry.GroupId)==group:Under(FindAccountGroup(entry.GroupId),group);}
        internal static List<string> ParseTags(string text){var tags=(text??"").Split(new[]{';',','},StringSplitOptions.RemoveEmptyEntries).Select(t=>t.Trim()).Where(t=>t.Length>0).Distinct(StringComparer.CurrentCultureIgnoreCase).ToList();if(tags.Count>32||tags.Any(t=>t.Length>64||t.Any(char.IsControl)))throw new IOException("Можно добавить до 32 меток, каждая не длиннее 64 символов.");return tags;}

        const int MaxAttachment=2*1024*1024,MaxAttachmentTotal=16*1024*1024;
        internal List<AccountAttachmentInfo> Attachments(string id){Ready();var entry=ActiveRecord(id,false);if(entry==null)throw new IOException("Запись не найдена.");return entry.Binaries.Select(p=>new AccountAttachmentInfo{Name=p.Key,Size=p.Value.Length}).ToList();}
        internal void AddAttachment(string id,string path){Ready();var entry=ActiveRecord(id,false);if(entry==null)throw new IOException("Запись не найдена.");var name=Path.GetFileName(path);if(string.IsNullOrWhiteSpace(name)||name.Length>200||name.Any(char.IsControl))throw new IOException("Недопустимое название файла.");if(entry.Binaries.Get(name)!=null)throw new IOException("Файл с таким названием уже прикреплён. Удалите его перед заменой.");var bytes=SafeStorage.ReadBounded(path,MaxAttachment);try{if(entry.Binaries.Sum(b=>(long)b.Value.Length)+bytes.Length>MaxAttachmentTotal)throw new IOException("Размер вложений одной записи не должен превышать 16 МБ.");entry.CreateBackup(db);entry.Binaries.Set(name,new ProtectedBinary(true,bytes));entry.Touch(true,false);entry.MaintainBackups(db);}finally{Array.Clear(bytes,0,bytes.Length);}}
        internal void RemoveAttachment(string id,string name){Ready();var entry=ActiveRecord(id,false);if(entry==null||entry.Binaries.Get(name)==null)throw new IOException("Вложение больше не доступно.");entry.CreateBackup(db);entry.Binaries.Remove(name);entry.Touch(true,false);entry.MaintainBackups(db);}
        internal void ExportAttachment(string id,string name,string destination){Ready();var entry=ActiveRecord(id,false);var binary=entry==null?null:entry.Binaries.Get(name);if(binary==null)throw new IOException("Вложение больше не доступно.");var bytes=binary.ReadData();try{Paths.AtomicWriteStream(destination,s=>s.Write(bytes,0,bytes.Length));}finally{Array.Clear(bytes,0,bytes.Length);}}

        // KeePass field-reference syntax (SprEngine). WinUp creates UUID references so names can change.
        sealed class ReferenceBudget{internal int Steps,Characters;}
        internal string ResolveText(string raw){Ready();return ResolveText(raw,new HashSet<string>(),0,new ReferenceBudget());}
        string ResolveText(string raw,HashSet<string> seen,int depth,ReferenceBudget budget){
            if(string.IsNullOrEmpty(raw)||raw.IndexOf("{REF:",StringComparison.OrdinalIgnoreCase)<0)return raw;
            if(depth>=20||raw.Length>1024*1024)throw new IOException("Слишком длинная цепочка ссылок между полями.");
            var resolved=Regex.Replace(raw,@"\{REF:([TUPANI])@([TUPANIO]):([^{}]+)\}",m=>{
                if(++budget.Steps>1024)throw new IOException("В поле слишком много связанных ссылок.");
                char wanted=char.ToUpperInvariant(m.Groups[1].Value[0]),scan=char.ToUpperInvariant(m.Groups[2].Value[0]);string query=m.Groups[3].Value;
                PwEntry entry;
                if(scan=='I')entry=AccountRecords().FirstOrDefault(e=>e.Uuid.ToHexString().Equals(query,StringComparison.OrdinalIgnoreCase));
                else {var sp=SearchParameters.None;sp.SearchString=query;sp.RespectEntrySearchingDisabled=false;sp.SearchInTitles=scan=='T';sp.SearchInUserNames=scan=='U';sp.SearchInPasswords=scan=='P';sp.SearchInUrls=scan=='A';sp.SearchInNotes=scan=='N';sp.SearchInOther=scan=='O';var found=new KeePassLib.Collections.PwObjectList<PwEntry>();db.RootGroup.SearchEntries(sp,found);entry=found.FirstOrDefault(e=>AccountRecords().Contains(e));}
                if(entry==null)throw new IOException("Запись, на которую ссылается поле, не найдена. Проверьте ссылки между записями.");
                string field=wanted=='P'?"Password":wanted=='U'?"UserName":wanted=='T'?"Title":wanted=='A'?"URL":wanted=='N'?"Notes":null;
                string key=entry.Uuid.ToHexString()+":"+wanted;if(!seen.Add(key))throw new IOException("Ссылки между полями образуют замкнутую цепочку.");
                string value=wanted=='I'?entry.Uuid.ToHexString():wanted=='P'?ReadSecret(entry,field):new string(entry.Strings.ReadSafe(field).ToCharArray());string expanded=null;try{expanded=ResolveText(value,seen,depth+1,budget)??"";budget.Characters=checked(budget.Characters+expanded.Length);if(budget.Characters>1024*1024)throw new IOException("Результат ссылок слишком большой. Сократите связанные поля.");return new string(expanded.ToCharArray());}finally{seen.Remove(key);if(!object.ReferenceEquals(value,expanded))Secure.Wipe(expanded);Secure.Wipe(value);}
            },RegexOptions.IgnoreCase);
            if(resolved.Length>1024*1024||resolved.IndexOf("{REF:",StringComparison.OrdinalIgnoreCase)>=0)throw new IOException("Неправильная или слишком длинная ссылка между полями.");return resolved;
        }
        internal void ValidateReferenceChange(LoginEntry proposed){Ready();var record=ActiveRecord(proposed.Id,false);if(record==null)return;var login=record.Strings.Get("UserName");var password=record.Strings.Get("Password");string raw=proposed.Password;try{record.Strings.Set("UserName",new ProtectedString(true,proposed.Login??""));record.Strings.Set("Password",new ProtectedString(true,raw??""));ResolveText(proposed.Login);string resolved=ResolveText(raw);if(!object.ReferenceEquals(raw,resolved))Secure.Wipe(resolved);}finally{record.Strings.Set("UserName",login??ProtectedString.Empty);record.Strings.Set("Password",password??ProtectedString.Empty);Secure.Wipe(raw);}}
        internal static string Reference(string id,char field){if(id==null||id.Length!=32||id.Any(c=>!Uri.IsHexDigit(c))||"TUPANI".IndexOf(field)<0)throw new IOException("Недопустимая ссылка.");return "{REF:"+field+"@I:"+id+"}";}
        internal void BindReferences(){foreach(var e in Entries){e.ResolveField=ResolveText;foreach(var f in e.CustomFields)f.ResolveField=ResolveText;}}

        internal DatabaseMerge PreviewMerge(string path,string password,byte[] key){
            Ready();if(Proc.SameFile(path,KdbxPath))throw new IOException("Выберите копию базы с другого устройства.");var merge=new DatabaseMerge{Other=new PwDatabase()};
            try{KdbxSafety.OpenDatabase(merge.Other,path,MakeKey(password,key),NullLog);merge.SameDatabase=db.RootGroup.Uuid.Equals(merge.Other.RootGroup.Uuid);if(!merge.SameDatabase)throw new IOException("Это другая база. Для объединения выберите копию этой базы с другого устройства. Аккаунты из другого менеджера добавляйте через импорт.");merge.LocalStamp=MergeStamp();
                var local=WalkGroups(db.RootGroup).SelectMany(g=>g.Entries).ToDictionary(e=>e.Uuid.ToHexString());
                var remote=WalkGroups(merge.Other.RootGroup).SelectMany(g=>g.Entries).ToDictionary(e=>e.Uuid.ToHexString());
                foreach(var entry in remote.Values){PwEntry current;if(!local.TryGetValue(entry.Uuid.ToHexString(),out current)){var deleted=db.DeletedObjects.FirstOrDefault(d=>d.Uuid.Equals(entry.Uuid));if(deleted==null){merge.Added++;continue;}merge.Conflicts.Add(new MergeConflict{Id=entry.Uuid.ToHexString(),Name=entry.Strings.ReadSafe("Title"),LocalTime=deleted.DeletionTime,OtherTime=entry.LastModificationTime,LocalDeleted=true});continue;}if(!current.EqualsEntry(entry,PwCompareOptions.IgnoreTimes|PwCompareOptions.IgnoreHistory|PwCompareOptions.IgnoreParentGroup,KeePassLib.MemProtCmpMode.Full)||!current.ParentGroup.Uuid.Equals(entry.ParentGroup.Uuid))merge.Conflicts.Add(new MergeConflict{Id=entry.Uuid.ToHexString(),Name=entry.Strings.ReadSafe("Title"),LocalTime=current.LastModificationTime>current.LocationChanged?current.LastModificationTime:current.LocationChanged,OtherTime=entry.LastModificationTime>entry.LocationChanged?entry.LastModificationTime:entry.LocationChanged});}
                foreach(var deleted in merge.Other.DeletedObjects){PwEntry current;if(local.TryGetValue(deleted.Uuid.ToHexString(),out current)&&!remote.ContainsKey(deleted.Uuid.ToHexString()))merge.Conflicts.Add(new MergeConflict{Id=current.Uuid.ToHexString(),Name=current.Strings.ReadSafe("Title"),LocalTime=current.LastModificationTime,OtherTime=deleted.DeletionTime,OtherDeleted=true});}
                merge.Removed=merge.Other.DeletedObjects.Count(d=>local.ContainsKey(d.Uuid.ToHexString())&&local[d.Uuid.ToHexString()].LastModificationTime<=d.DeletionTime);return merge;
            }catch{merge.Dispose();throw;}
        }
        string MergeStamp(){return RecordRevision+"|"+string.Join(";",WalkGroups(db.RootGroup).SelectMany(g=>g.Entries).Select(e=>e.Uuid.ToHexString()+":"+e.ParentGroup.Uuid.ToHexString()+":"+e.LocationChanged.Ticks+":"+e.LastModificationTime.Ticks+":"+e.History.UCount))+"|"+string.Join(";",AccountGroups().Select(g=>g.Id+g.ParentId+g.Name))+"|"+string.Join(";",db.DeletedObjects.Select(d=>d.Uuid.ToHexString()+":"+d.DeletionTime.Ticks));}
        internal void ApplyMerge(DatabaseMerge merge){
            Ready();if(merge.Other==null||MergeStamp()!=merge.LocalStamp)throw new IOException("База изменилась после сравнения. Сравните копии заново.");
            var overrides=new Dictionary<string,PwEntry>();var parents=new Dictionary<string,PwUuid>();var deletedChoices=new List<string>();foreach(var row in merge.Conflicts.Where(c=>c.Choice!="Более новая")){if(row.Choice!="Эта база"&&row.Choice!="Вторая копия")throw new IOException("Выберите допустимый вариант объединения.");var source=row.Choice=="Эта база"?db:merge.Other;bool deleted=row.Choice=="Эта база"?row.LocalDeleted:row.OtherDeleted;if(deleted){deletedChoices.Add(row.Id);continue;}var entry=source.RootGroup.FindEntry(new PwUuid(KeePassLib.Utility.MemUtil.HexStringToByteArray(row.Id)),true);if(entry!=null){overrides[row.Id]=entry.CloneDeep();parents[row.Id]=entry.ParentGroup.Uuid;}}
            db.MergeIn(merge.Other,PwMergeMethod.Synchronize);
            foreach(var pair in overrides){var entry=db.RootGroup.FindEntry(pair.Value.Uuid,true);var parent=db.RootGroup.FindGroup(parents[pair.Key],true)??db.RootGroup;if(entry==null){parent.AddEntry(pair.Value,true);entry=pair.Value;}else{entry.CreateBackup(db);entry.AssignProperties(pair.Value,false,false,false);if(entry.ParentGroup!=parent){entry.ParentGroup.Entries.Remove(entry);parent.AddEntry(entry,true);}}entry.LastModificationTime=new[]{DateTime.UtcNow,entry.LastModificationTime,merge.Conflicts.First(c=>c.Id==pair.Key).OtherTime,merge.Conflicts.First(c=>c.Id==pair.Key).LocalTime}.Max().AddTicks(1);entry.LocationChanged=entry.LastModificationTime;foreach(var tombstone in db.DeletedObjects.Where(d=>d.Uuid.Equals(entry.Uuid)).ToArray())db.DeletedObjects.Remove(tombstone);entry.MaintainBackups(db);}
            foreach(var id in deletedChoices){var uuid=new PwUuid(KeePassLib.Utility.MemUtil.HexStringToByteArray(id));var entry=db.RootGroup.FindEntry(uuid,true);if(entry!=null)entry.ParentGroup.Entries.Remove(entry);foreach(var old in db.DeletedObjects.Where(d=>d.Uuid.Equals(uuid)).ToArray())db.DeletedObjects.Remove(old);var row=merge.Conflicts.First(c=>c.Id==id);db.DeletedObjects.Add(new PwDeletedObject(uuid,new[]{DateTime.UtcNow,row.LocalTime,row.OtherTime}.Max().AddTicks(1)));}
            RecordRevision++;ReloadRecords();
        }
        internal void SaveBeforeMerge(string path){Ready();SaveDatabase(path);}
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KeePassLib;
using KeePassLib.Security;
namespace WinUp {
    public sealed class SecureNoteInfo { public string Id {get;set;} public string Title {get;set;} public DateTime Modified {get;set;} }
    public sealed partial class KdbxStore {
        PwGroup NoteGroup(bool create){var group=db.RootGroup.Groups.FirstOrDefault(g=>g.CustomData.Get("WinUp.Notes")=="1");if(group==null&&create){group=new PwGroup(true,true,"Заметки",PwIcon.Note);group.CustomData.Set("WinUp.Notes","1");db.RootGroup.AddGroup(group,true);}return group;}
        IEnumerable<PwEntry> NoteRecords(){return WalkGroups(db.RootGroup).Where(g=>!Under(g,Trash(false))).SelectMany(g=>g.Entries).Where(e=>GetStr(e,"WinUp.Kind")=="note");}
        public List<SecureNoteInfo> NoteItems(){Ready();return NoteRecords().Select(e=>new SecureNoteInfo{Id=e.Uuid.ToHexString(),Title=e.Strings.ReadSafe(PwDefs.TitleField),Modified=e.LastModificationTime}).OrderByDescending(n=>n.Modified).ToList();}
        public string ReadNote(string id){Ready();var entry=NoteRecords().FirstOrDefault(e=>e.Uuid.ToHexString()==id);if(entry==null)throw new IOException("Заметка больше не доступна.");return ReadSecret(entry,PwDefs.NotesField);}
        public string PutNote(string id,string title,string text){Ready();db.MemoryProtection.ProtectNotes=true;title=(title??"").Trim();if(title.Length==0||title.Length>160||title.Any(char.IsControl))throw new IOException("Укажите заголовок до 160 символов.");if((text??"").Length>262144)throw new IOException("Заметка слишком длинная (максимум 262144 символа).");var entry=NoteRecords().FirstOrDefault(e=>e.Uuid.ToHexString()==id);bool found=entry!=null;if(!found){if(!string.IsNullOrEmpty(id))throw new IOException("Заметка больше не доступна.");entry=new PwEntry(true,true);NoteGroup(true).AddEntry(entry,true);}UpdateWithHistory(entry,e=>{SetStr(e,"WinUp.Kind","note");e.Strings.Set(PwDefs.TitleField,new ProtectedString(false,title));e.Strings.Set(PwDefs.NotesField,ProtectedUtf8(text??""));},found);return entry.Uuid.ToHexString();}
        public void DeleteNote(string id){Ready();var entry=NoteRecords().FirstOrDefault(e=>e.Uuid.ToHexString()==id);if(entry==null)throw new IOException("Заметка больше не доступна.");MoveToTrash(entry,false);}
    }
}

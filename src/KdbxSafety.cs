using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Cryptography.KeyDerivation;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace WinUp {
    // KeePass authenticates KDF parameters only after using them. Inspect public
    // lengths and work factors first, without deriving any key or reading secrets.
    internal static class KdbxSafety {
        internal const long MaxDatabaseBytes=256L*1024*1024;
        internal const int MaxHeaderBytes=1024*1024;
        internal const int MaxKdfBytes=64*1024;
        internal const int MaxBlockBytes=4*1024*1024;
        internal const int MaxBlockCount=4096;
        internal const ulong MaxArgonMemory=512UL*1024*1024;
        internal const ulong MaxArgonIterations=1024;
        internal const ulong MaxArgonWork=64UL*1024*1024*1024;
        internal const uint MaxArgonParallelism=16;
        internal const ulong MaxAesRounds=10000000;
        static InvalidDataException Bad(string text) {return new InvalidDataException("База KDBX отклонена: "+text);}
        static byte[] Exact(BinaryReader reader,int count) {
            if(count<0 || count>MaxHeaderBytes || count>reader.BaseStream.Length-reader.BaseStream.Position)
                throw Bad("повреждённая или слишком большая длина поля.");
            byte[] bytes=reader.ReadBytes(count);if(bytes.Length!=count)throw Bad("файл оборван.");return bytes;
        }
        internal static void OpenDatabase(PwDatabase database,string path,CompositeKey key,IStatusLogger logger) {
            path=Path.GetFullPath(path);SafePaths.NoReparseParents(path);
            using(var directories=SourceLease.HoldDirectories(Path.GetDirectoryName(path)))
            using(var held=SafeStorage.OpenReadNoFollow(path)) {
                Validate(held);
                // The file and every parent remain held while KeePass opens the same
                // path, so the checked header cannot be exchanged before key derivation.
                database.Open(IOConnectionInfo.FromPath(path),key,logger);
            }
        }
        internal static void Validate(Stream source) {
            if(source==null || !source.CanRead || !source.CanSeek)throw Bad("требуется обычный локальный файл.");
            long saved=source.Position;
            try {
                source.Position=0;
                if(source.Length<12 || source.Length>MaxDatabaseBytes)throw Bad("допустимый размер файла — до 256 МиБ.");
                using(var reader=new BinaryReader(source,Encoding.UTF8,true)) {
                    if(reader.ReadUInt32()!=0x9AA2D903 || reader.ReadUInt32()!=0xB54BFB67)throw Bad("неверная сигнатура формата.");
                    uint version=reader.ReadUInt32();
                    if(version<0x00040000)throw Bad("KDBX 3 не поддерживается. Откройте копию в KeePass или KeePassXC и сохраните её в KDBX 4; параметры защиты автоматически не уменьшаются.");
                    if(version>0x00040001)throw Bad("нужна версия WinUp с поддержкой этого нового формата.");
                    var seen=new HashSet<byte>();bool ended=false;KdfParameters parameters=null;
                    for(int field=0;field<128;field++) {
                        if(source.Length-source.Position<5)throw Bad("заголовок оборван.");
                        byte id=reader.ReadByte();int count=reader.ReadInt32();
                        if(count<0 || count>MaxHeaderBytes || source.Position+count>MaxHeaderBytes)throw Bad("заголовок превышает 1 МиБ или содержит неверную длину.");
                        if(!seen.Add(id))throw Bad("повторяющееся поле заголовка.");
                        if(id==11 && count>MaxKdfBytes)throw Bad("описание KDF превышает 64 КиБ.");
                        byte[] data=Exact(reader,count);
                        if(id==0) {
                            if(data.Length!=4 || !data.SequenceEqual(new byte[]{13,10,13,10}))throw Bad("повреждён конец заголовка.");
                            ended=true;break;
                        }
                        if(id==5 || id==6 || id==8 || id==9 || id==10)throw Bad("поля KDBX 3 не допускаются в заголовке KDBX 4.");
                        if(id==11) {ValidateDictionary(data);parameters=KdfParameters.DeserializeExt(data);ValidateKdfParameters(parameters);}
                        if(id==12)ValidateDictionary(data);
                    }
                    if(!ended || parameters==null || !seen.Contains(2) || !seen.Contains(3) || !seen.Contains(4) || !seen.Contains(7))
                        throw Bad("в заголовке отсутствуют обязательные поля.");
                    long headerEnd=source.Position;
                    if(source.Length-headerEnd<100)throw Bad("нет контрольных сумм и блоков данных.");
                    byte[] digest=Exact(reader,32);
                    source.Position=0;byte[] header=Exact(reader,(int)headerEnd);
                    using(var sha=SHA256.Create())if(!sha.ComputeHash(header).SequenceEqual(digest))throw Bad("контрольная сумма заголовка не совпала.");
                    source.Position=headerEnd+64;
                    // HMAC bytes and block lengths are public. Lengths are used for
                    // allocation by KeePass before each block HMAC is verified.
                    for(int block=0;block<MaxBlockCount;block++) {
                        if(source.Length-source.Position<36)throw Bad("блок данных оборван.");
                        source.Position+=32;int count=reader.ReadInt32();
                        if(count<0 || count>MaxBlockBytes || count>source.Length-source.Position)
                            throw Bad("блок данных превышает 4 МиБ или оборван.");
                        source.Position+=count;
                        if(count==0) {
                            if(source.Position!=source.Length)throw Bad("лишние данные после конечного блока.");
                            return;
                        }
                    }
                    throw Bad("слишком много блоков данных.");
                }
            } catch(EndOfStreamException) {throw Bad("файл оборван.");}
            finally {source.Position=saved;}
        }
        internal static void ValidateDictionary(byte[] data) {
            using(var source=new MemoryStream(data,false))using(var reader=new BinaryReader(source,Encoding.UTF8,true)) {
                if(source.Length<3 || (reader.ReadUInt16()&0xFF00)>0x0100)throw Bad("неподдерживаемое описание параметров.");
                var names=new HashSet<string>(StringComparer.Ordinal);
                for(int entry=0;entry<128;entry++) {
                    if(source.Position>=source.Length)throw Bad("описание параметров оборвано.");
                    byte type=reader.ReadByte();
                    if(type==0) {if(source.Position!=source.Length)throw Bad("лишние байты в описании параметров.");return;}
                    if(source.Length-source.Position<4)throw Bad("длина имени параметра оборвана.");
                    int length=reader.ReadInt32();
                    if(length<1 || length>256)throw Bad("имя параметра имеет недопустимую длину.");
                    string name;
                    try {name=new UTF8Encoding(false,true).GetString(Exact(reader,length));}catch(DecoderFallbackException){throw Bad("имя параметра повреждено.");}
                    if(!names.Add(name))throw Bad("повторяющийся параметр.");
                    if(source.Length-source.Position<4)throw Bad("длина параметра оборвана.");
                    int count=reader.ReadInt32();
                    int exact=type==4 || type==12 ? 4 : type==5 || type==13 ? 8 : type==8 ? 1 : -1;
                    if(exact<0 && type!=24 && type!=66 || exact>=0 && count!=exact)throw Bad("неверный тип или размер параметра.");
                    Exact(reader,count);
                }
                throw Bad("слишком много параметров.");
            }
        }
        internal static void ValidateKdfParameters(KdfParameters parameters) {
            if(parameters==null)throw Bad("неверное описание KDF.");
            var uuid=parameters.KdfUuid;
            if(uuid.Equals(new Argon2Kdf(Argon2Type.D).Uuid) || uuid.Equals(new Argon2Kdf(Argon2Type.ID).Uuid)) {
                ulong memory=parameters.GetUInt64(Argon2Kdf.ParamMemory,0),iterations=parameters.GetUInt64(Argon2Kdf.ParamIterations,0);
                uint parallelism=parameters.GetUInt32(Argon2Kdf.ParamParallelism,0),version=parameters.GetUInt32(Argon2Kdf.ParamVersion,0);
                byte[] salt=parameters.GetByteArray(Argon2Kdf.ParamSalt);
                if(memory<8192 || memory>MaxArgonMemory || iterations<1 || iterations>MaxArgonIterations ||
                    parallelism<1 || parallelism>MaxArgonParallelism || memory<8192UL*parallelism || memory>MaxArgonWork/iterations)
                    throw Bad("параметры Argon2 превышают безопасный бюджет WinUp (512 МиБ памяти, 1024 итерации, 16 потоков, суммарная работа до 64 ГиБ). Параметры базы не изменены; чрезмерно сильную базу открывайте в отдельном совместимом приложении.");
                if(version<0x10 || version>0x13 || salt==null || salt.Length<8 || salt.Length>1024)throw Bad("неверная версия или соль Argon2.");
                return;
            }
            if(uuid.Equals(new AesKdf().Uuid)) {
                if(parameters.GetTypeOf(AesKdf.ParamRounds)!=typeof(ulong) || parameters.GetUInt64(AesKdf.ParamRounds,ulong.MaxValue)>MaxAesRounds)
                    throw Bad("AES-KDF превышает бюджет в 10 000 000 раундов. Параметры защиты базы не изменены.");
                byte[] seed=parameters.GetByteArray(AesKdf.ParamSeed);
                if(seed==null || seed.Length!=32)throw Bad("неверная соль AES-KDF.");
                return;
            }
            throw Bad("этот алгоритм KDF не поддерживается безопасной проверкой WinUp.");
        }
    }
}

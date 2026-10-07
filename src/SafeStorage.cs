using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinUp
{
    internal static class SafeStorage
    {
        internal static string ReadTextBounded(string path, int maximum)
        {
            using (var bytes = new MemoryStream(ReadBounded(path, maximum), false))
            using (var reader = new StreamReader(bytes, System.Text.Encoding.UTF8, true)) return reader.ReadToEnd();
        }
        internal static FileStream OpenReadNoFollow(string path)
        {
            var handle = CreateFile(path, 0x80000000u, 1, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero);
            HandleInfo info;
            if (handle.IsInvalid || !GetFileInformationByHandle(handle, out info) || (info.Attributes & 0x410u) != 0)
            {
                handle.Dispose();
                throw new IOException("Файл занят, содержит ссылку или не является обычным файлом.");
            }
            try { return new FileStream(handle, FileAccess.Read); }
            catch { handle.Dispose(); throw; }
        }
        internal static byte[] ReadBounded(string path, int maximum)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (stream.Length > maximum) throw new InvalidDataException("Файл превышает допустимый размер: " + Path.GetFileName(path));
                var bytes = new byte[(int)stream.Length];
                int offset = 0, count;
                while (offset < bytes.Length && (count = stream.Read(bytes, offset, bytes.Length - offset)) > 0) offset += count;
                if (offset != bytes.Length) throw new EndOfStreamException("Файл изменился во время чтения.");
                return bytes;
            }
        }
        [StructLayout(LayoutKind.Sequential)] struct HandleInfo
        {
            internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
                Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle file, out HandleInfo info);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind, ref int info, uint size);

        // Never follow a link while overwriting. Delete the verified object by its
        // open handle, so a replaced pathname cannot select another file.
        internal static void WipeFile(string path)
        {
            path = Path.GetFullPath(path);
            if (Path.GetFileName(path).IndexOf(':') >= 0) throw new IOException("Дополнительные потоки не поддерживаются.");
            using (SourceLease.HoldDirectories(Path.GetDirectoryName(path)))
            using (var handle = CreateFile(path, 0x40010080u, 0, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero))
            {
                HandleInfo info;
                if (handle.IsInvalid) throw new IOException("Файл занят или недоступен для удаления.");
                if (!GetFileInformationByHandle(handle, out info) || (info.Attributes & 0x410u) != 0 || info.Links != 1)
                    throw new IOException("Удаление остановлено: файл содержит ссылку или имеет несколько имён.");
                long length = ((long)info.SizeHigh << 32) | info.SizeLow;
                var junk = Vault.Random((int)Math.Min(Math.Max(length, 1), 4 * 1024 * 1024));
                try
                {
                    using (var stream = new FileStream(handle, FileAccess.Write))
                    {
                        for (long offset = 0; offset < length; offset += junk.Length)
                            stream.Write(junk, 0, (int)Math.Min(junk.Length, length - offset));
                        stream.Flush(true);
                        int disposition = 1;
                        if (!SetFileInformationByHandle(handle, 4, ref disposition, 4))
                            throw new IOException("Не удалось удалить проверенный файл.");
                    }
                }
                finally { Array.Clear(junk, 0, junk.Length); }
            }
        }
    }
}

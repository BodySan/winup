using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace WinUp
{
    // Windows protects the retained buffer for this process. Plaintext exists only in
    // short-lived copies owned by the caller. No fallback to an unprotected buffer.
    sealed class SecretBytes : IDisposable
    {
        byte[] protectedData;
        int length;
        readonly object sync = new object();
        public bool HasValue { get { lock (sync) return protectedData != null; } }

        public void Set(byte[] data)
        {
            byte[] next = null;
            if (data != null)
            {
                var inputPin = GCHandle.Alloc(data, GCHandleType.Pinned);
                GCHandle nextPin = default(GCHandle);
                try
                {
                next = new byte[checked(((data.Length / 16) + 1) * 16)];
                nextPin = GCHandle.Alloc(next, GCHandleType.Pinned);
                Buffer.BlockCopy(data, 0, next, 0, data.Length);
                try { ProtectedMemory.Protect(next, MemoryProtectionScope.SameProcess); }
                catch { Array.Clear(next, 0, next.Length); throw; }
                }
                finally { if (nextPin.IsAllocated) nextPin.Free(); inputPin.Free(); }
            }
            lock (sync)
            {
                if (protectedData != null) Array.Clear(protectedData, 0, protectedData.Length);
                protectedData = next;
                length = data == null ? 0 : data.Length;
            }
        }

        public byte[] Read()
        {
            lock (sync)
            {
                if (protectedData == null) return null;
                var copy = (byte[])protectedData.Clone();
                var pin = GCHandle.Alloc(copy, GCHandleType.Pinned);
                try
                {
                    ProtectedMemory.Unprotect(copy, MemoryProtectionScope.SameProcess);
                    var result = new byte[length];
                    Buffer.BlockCopy(copy, 0, result, 0, length);
                    return result;
                }
                finally { Array.Clear(copy, 0, copy.Length); pin.Free(); }
            }
        }
        public void Dispose() { Set(null); }
    }

    sealed class SecretText
    {
        readonly SecretBytes value = new SecretBytes();
        public bool HasValue { get { return value.HasValue; } }
        public void Set(string text)
        {
            if (text == null) { value.Dispose(); return; }
            var textPin = GCHandle.Alloc(text, GCHandleType.Pinned);
            try
            {
            var bytes = new byte[checked(text.Length * 2)];
            var bytePin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                for (int i = 0; i < text.Length; i++)
                { bytes[i * 2] = (byte)text[i]; bytes[i * 2 + 1] = (byte)(text[i] >> 8); }
                value.Set(bytes);
            }
            finally { Array.Clear(bytes, 0, bytes.Length); bytePin.Free(); }
            }
            finally { textPin.Free(); }
        }
        public string Read()
        {
            var bytes = value.Read();
            if (bytes == null) return null;
            var bytePin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
            var chars = new char[bytes.Length / 2];
            var charPin = GCHandle.Alloc(chars, GCHandleType.Pinned);
            try
            {
                for (int i = 0; i < chars.Length; i++) chars[i] = (char)(bytes[i * 2] | bytes[i * 2 + 1] << 8);
                return new string(chars);
            }
            finally { Array.Clear(chars, 0, chars.Length); charPin.Free(); }
            }
            finally { Array.Clear(bytes, 0, bytes.Length); bytePin.Free(); }
        }
        public T Use<T>(Func<string, T> action)
        {
            var text = Read();
            var pin = text == null ? default(GCHandle) : GCHandle.Alloc(text, GCHandleType.Pinned);
            try { return action(text); }
            finally { Secure.Wipe(text); if (pin.IsAllocated) pin.Free(); }
        }
        public void Clear() { value.Dispose(); }
    }
}

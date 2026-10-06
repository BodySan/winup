"""Independent WinZip AE-2 decoder for the synthetic Sandbox export (no plaintext output)."""
import hashlib
import hmac
import struct
import sys
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

path = Path(sys.argv[1]).resolve()
if path.name != 'audit-export.zip' or 'test' not in path.parts or 'audit' not in path.parts:
    raise SystemExit('Synthetic audit archive only')
raw = path.read_bytes()
password = b'Synthetic-Zip-7x$Long-Audit-Key'
with zipfile.ZipFile(path) as archive:
    assert len(archive.infolist()) == 3
    for entry in archive.infolist():
        start = entry.header_offset
        header = struct.unpack_from('<I5H3I2H', raw, start)
        signature, _, flags, method, _, _, crc, size, length, name_len, extra_len = header
        assert signature == 0x04034B50 and method == 99 and flags & 1
        extra = raw[start + 30 + name_len:start + 30 + name_len + extra_len]
        assert struct.unpack('<HHH2sBH', extra) == (0x9901, 7, 2, b'AE', 3, 0)
        offset = start + 30 + name_len + extra_len
        payload = raw[offset:offset + size]
        salt, verifier, ciphertext, tag = payload[:16], payload[16:18], payload[18:-10], payload[-10:]
        keys = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=66)
        assert hmac.compare_digest(verifier, keys[64:])
        assert hmac.compare_digest(tag, hmac.new(keys[32:64], ciphertext, hashlib.sha1).digest()[:10])
        encryptor = Cipher(algorithms.AES(keys[:32]), modes.ECB()).encryptor()
        plain = bytearray()
        for at in range(0, len(ciphertext), 16):
            stream = encryptor.update((at // 16 + 1).to_bytes(16, 'little'))
            plain.extend(a ^ b for a, b in zip(ciphertext[at:at + 16], stream))
        assert len(plain) == length == entry.file_size
        marker = b'JBSWY3DPEHPK3PXP' if entry.filename == 'otp.txt' else b'Audit-only-secret!'
        assert marker in plain
        plain[:] = bytes(len(plain))
        print('PASS independently-authenticated-and-decrypted ' + entry.filename)
print('TOTAL passes=3')

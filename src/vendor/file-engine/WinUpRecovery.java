// Recovery-key encoding adapted from Cryptomator 1.19.3 RecoveryKeyFactory.
// GPL-3.0; original source and hashes: recovery-UPSTREAM.md and upstream archive.
import java.util.Arrays;
import com.google.common.base.Preconditions;
import com.google.common.hash.Hashing;

final class WinUpRecovery {
    private static final WordEncoder words = new WordEncoder();
    static String encode(byte[] rawKey) {
        Preconditions.checkArgument(rawKey.length == 64, "key should be 64 bytes");
        byte[] paddedKey = Arrays.copyOf(rawKey, 66);
        try { Hashing.crc32().hashBytes(rawKey).writeBytesTo(paddedKey, 64, 2); return words.encodePadded(paddedKey); }
        finally { Arrays.fill(paddedKey, (byte) 0); }
    }
    static byte[] decode(String recoveryKey) {
        byte[] paddedKey = new byte[0], rawKey = new byte[0]; boolean accepted = false;
        try {
            paddedKey = words.decode(recoveryKey.trim().toLowerCase(java.util.Locale.ROOT));
            Preconditions.checkArgument(paddedKey.length == 66, "Recovery key doesn't consist of 66 bytes.");
            rawKey = Arrays.copyOf(paddedKey, 64);
            byte[] crc = Hashing.crc32().hashBytes(rawKey).asBytes();
            Preconditions.checkArgument(crc[0] == paddedKey[64] && crc[1] == paddedKey[65], "Recovery key has invalid CRC.");
            accepted = true;return rawKey;
        } finally { Arrays.fill(paddedKey,(byte)0);if(!accepted)Arrays.fill(rawKey,(byte)0); }
    }
}

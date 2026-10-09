# Cryptomator recovery key, version 1.19.3

Original project: https://github.com/cryptomator/cryptomator/tree/1.19.3

Original files: `src/main/java/org/cryptomator/ui/recoverykey/RecoveryKeyFactory.java`,
`WordEncoder.java`, `src/main/resources/i18n/4096words_en.txt` and `LICENSE.txt`.
License: GNU GPL v3; complete text in `licenses/Cryptomator-Recovery-GPL.txt`.
Unmodified source snapshot: `vendor/upstream/cryptomator-recovery-1.19.3.zip`;
archive digest is recorded in `vendor/upstream/SHA256.json`.

WinUp changes: WordEncoder has its package and dependency-injection annotations removed.
WinUpRecovery adapts the original encode/decode/checksum methods, accepts lowercase input,
and clears failed decoded keys. The original dictionary is unchanged. Password changes
and reset use the original Cryptolib MasterkeyFileAccess; WinUp verifies the vault config
against the key and writes the replacement masterkey atomically after creating a backup.
No custom encryption format is introduced.

SHA-256 of the original files:

0598383B83327D5E98DF17561CAD8E01257DA04BB9C710A0AA4CB11832F1441C RecoveryKeyFactory.java
AE52A9C4E101ACE15E1DE0518F5665DFE5D0C090BFB159FE59229D7263BB1292 WordEncoder.java
A66B733E516289FBE2A0F9382D450965EDF4C9657A596035D34D1AE8A01CE175 4096words_en.txt
C53A65C2FD561C87EAABF1072EF5DCAB8653042BC15308465F52413585EB6271 LICENSE.txt

// WinUp adapter. Cryptomator cryptofs/cryptolib are used unchanged.
// AGPL-3.0-or-later. Commands/passwords travel only over inherited stdin.
import java.io.*;
import java.net.URI;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.channels.*;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.*;
import java.util.*;
import org.cryptomator.cryptofs.*;
import org.cryptomator.cryptolib.api.*;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;
import org.cryptomator.integrations.common.IntegrationsLoader;
import org.cryptomator.integrations.mount.*;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class WinUpFiles {
    private static FileSystem fs;
    private static Mount mount;
    private static Path storage;
    private static Path pathGuard;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RNG = new SecureRandom();
    // The native launcher can choose a Windows console code page for System.out.
    // Protocol bytes always use UTF-8, including Cyrillic and non-BMP filenames.
    private static final PrintStream PROTOCOL = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
    private static String decode(String s) { return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8); }
    private static Path inside(String name) throws IOException {
        Path root = fs.getPath("/");
        Path p = root.resolve(name.replace('\\','/')).normalize();
        if (!p.startsWith(root) || name.contains(":")) throw new IOException("unsafe_path");
        for (String part : name.replace('\\','/').split("/")) if (part.equals("..")) throw new IOException("unsafe_path");
        for (Path part : p) if (part.toString().startsWith(".winup-import-")) throw new IOException("reserved_name");
        return p;
    }
    private static void reply(Object value) throws IOException { PROTOCOL.println("WUP2\t" + JSON.writeValueAsString(value)); PROTOCOL.flush(); }
    private static void open(String folder, String encoded, String guard, boolean create) throws Exception {
        if (fs != null) throw new IOException("already_open");
        Path vault = Path.of(folder).toAbsolutePath().normalize();
        storage = vault;
        if (!guard.matches("\\.winup-path-lease-[0-9a-f]{32}")) throw new IOException("unsafe_path_guard");
        pathGuard = vault.resolve(guard);
        if (!Files.isRegularFile(pathGuard, LinkOption.NOFOLLOW_LINKS)) throw new IOException("missing_path_guard");
        byte[] bytes = Base64.getDecoder().decode(encoded);
        CharBuffer chars = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
        try {
            var access = new MasterkeyFileAccess(new byte[0], RNG);
            if (create) {
                // The parent creates this directory exclusively and holds its
                // verified root before launching us. Never create/reopen an
                // unheld root between directory creation and key persistence.
                if (!Files.isDirectory(vault, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(vault)) throw new IOException("unsafe_vault_root");
                try (var entries = Files.list(vault)) { if (entries.anyMatch(p -> !p.equals(pathGuard))) throw new IOException("vault_root_not_empty"); }
                try (Masterkey key = Masterkey.generate(RNG)) {
                    access.persist(key, vault.resolve("masterkey.cryptomator"), chars);
                    var props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                        .withCipherCombo(CryptorProvider.Scheme.SIV_GCM).withKeyLoader(id -> key.copy()).build();
                    CryptoFileSystemProvider.initialize(vault, props, URI.create("masterkeyfile:masterkey.cryptomator"));
                }
            }
            chars.rewind();
            // Loading the master key also validates the password before any plaintext becomes accessible.
            try (Masterkey key = access.load(vault.resolve("masterkey.cryptomator"), chars)) {
                var props = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoader(id -> {
                    if (!id.equals(URI.create("masterkeyfile:masterkey.cryptomator"))) throw new IllegalArgumentException("unknown_key");
                    return key.copy();
                }).build();
                fs = CryptoFileSystemProvider.newFileSystem(vault, props);
            }
        } finally {
            Arrays.fill(bytes, (byte)0);
            if (chars.hasArray()) Arrays.fill(chars.array(), '\0');
            System.gc();
        }
    }
    private static byte[] hash(Path file) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1024 * 1024];
        try (InputStream in = Files.newInputStream(file)) {
            int n; while ((n = in.read(buffer)) >= 0) sha.update(buffer, 0, n);
            return sha.digest();
        } finally { Arrays.fill(buffer, (byte)0); }
    }
    private static void copyVerified(Path source, Path target) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1024 * 1024];
        try (InputStream in = Files.newInputStream(source); FileChannel channel = FileChannel.open(target,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)) {
            OutputStream out=Channels.newOutputStream(channel);
            int n; while ((n = in.read(buffer)) >= 0) { out.write(buffer,0,n); sha.update(buffer,0,n); }
            channel.force(true);
        } finally { Arrays.fill(buffer,(byte)0); }
        if (!MessageDigest.isEqual(sha.digest(), hash(target))) throw new IOException("verification_failed");
    }
    private static void removeStage(Path root) throws IOException {
        if (!Files.exists(root)) return;
        try (var walk = Files.walk(root)) {
            for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) Files.delete(p);
        }
    }
    public static final class ImportSnapshot {
        public String[] entries;
        public Map<String,String> zoneIdentifiers = new LinkedHashMap<>();
    }
    private static Path zoneRecord(Path destination) throws Exception {
        byte[] id=MessageDigest.getInstance("SHA-256").digest(destination.toString().getBytes(StandardCharsets.UTF_8));
        return fs.getPath("/.winup-import-metadata").resolve(HexFormat.of().formatHex(id)+".json");
    }
    private static byte[] zoneBytes(String encoded) throws IOException {
        if(encoded==null || encoded.length()>87384) throw new IOException("download_metadata_too_large");
        byte[] bytes=Base64.getDecoder().decode(encoded);
        if(bytes.length>65536) throw new IOException("download_metadata_too_large");
        return bytes;
    }
    private static byte[] restoredZone(Path file) throws Exception {
        // A folder import has one encrypted record for its immutable snapshot.
        // A later individual import has its own record, consulted first.
        for(Path ancestor=file;ancestor!=null;ancestor=ancestor.getParent()) {
            Path record=zoneRecord(ancestor);if(!Files.exists(record)) continue;
            if(Files.size(record)>6*1024*1024)throw new IOException("download_metadata_too_large");
            var zones=JSON.readValue(Files.readAllBytes(record),ImportSnapshot.class).zoneIdentifiers;
            String relative=ancestor.relativize(file).toString().replace('\\','/');
            if(zones.containsKey(relative))return zoneBytes(zones.get(relative));
        }
        return null;
    }
    private static void restoreZone(Path encryptedFile,Path staging) throws Exception {
        byte[] bytes=restoredZone(encryptedFile);if(bytes==null)return;
        try {
            var view=Files.getFileAttributeView(staging,UserDefinedFileAttributeView.class);
            if(view==null)throw new IOException("destination_cannot_preserve_download_metadata");
            view.write("Zone.Identifier",ByteBuffer.wrap(bytes));
            if(view.size("Zone.Identifier")!=bytes.length)throw new IOException("download_metadata_verification_failed");
            var check=ByteBuffer.allocate(bytes.length);view.read("Zone.Identifier",check);
            if(!MessageDigest.isEqual(bytes,check.array()))throw new IOException("download_metadata_verification_failed");
            Arrays.fill(check.array(),(byte)0);
        }finally{Arrays.fill(bytes,(byte)0);}
    }
    private static void importPath(Path source, Path destination, String manifest) throws Exception {
        // The parent WinUp process holds non-write/non-delete handles to every source.
        // Only it can delete originals, and only after this verified commit succeeds.
        // Iterate its immutable snapshot: a new child may be added to a directory
        // while the existing entries are held, but that child has no held handle.
        ImportSnapshot snapshot;
        if(manifest.stripLeading().startsWith("[")) { snapshot=new ImportSnapshot();snapshot.entries=JSON.readValue(manifest,String[].class); }
        else snapshot=JSON.readValue(manifest,ImportSnapshot.class);
        String[] entries = snapshot.entries;
        if (entries.length == 0 || entries.length > 10000 || !entries[0].isEmpty()) throw new IOException("bad_snapshot");
        if(snapshot.zoneIdentifiers==null || snapshot.zoneIdentifiers.size()>entries.length)throw new IOException("bad_download_metadata");
        Set<String> names=new HashSet<>(Arrays.asList(entries));
        Map<String,String> normalizedZones=new LinkedHashMap<>();
        for(var entry:snapshot.zoneIdentifiers.entrySet()) {
            if(!names.contains(entry.getKey()))throw new IOException("bad_download_metadata");
            byte[] bytes=zoneBytes(entry.getValue());Arrays.fill(bytes,(byte)0);
            String normalized=entry.getKey().replace('\\','/');if(normalizedZones.put(normalized,entry.getValue())!=null)throw new IOException("bad_download_metadata");
        }
        snapshot.zoneIdentifiers=normalizedZones;
        source = source.toAbsolutePath().normalize();
        if (Files.exists(destination)) throw new FileAlreadyExistsException("destination_exists");
        Path staging = destination.resolveSibling(".winup-import-" + UUID.randomUUID());
        Path metadata=zoneRecord(destination),metadataStage=null,metadataBackup=null;
        boolean metadataCommitted=false;
        boolean dataCommitted=false;
        boolean committed = false;
        try {
            if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectory(staging);
                Set<Path> seen = new HashSet<>();
                for (String relative : entries) {
                    Path relativePath = source.getFileSystem().getPath(relative);
                    if (relativePath.isAbsolute() || relative.contains(":")) throw new IOException("bad_snapshot");
                    for (Path component : relativePath) {
                        if (component.toString().equals("..")) throw new IOException("bad_snapshot");
                        if (component.toString().startsWith(".winup-import-")) throw new IOException("reserved_name");
                    }
                    Path p = source.resolve(relativePath).normalize();
                    if (!p.startsWith(source) || !seen.add(p)) throw new IOException("bad_snapshot");
                    if (Files.isSymbolicLink(p) || Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isOther()) throw new IOException("reparse_source");
                    if (p.equals(source)) { if(snapshot.zoneIdentifiers.containsKey(""))throw new IOException("directory_download_metadata_not_supported");continue; }
                    Path dst = staging.resolve(source.relativize(p).toString().replace('\\','/'));
                    if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {if(snapshot.zoneIdentifiers.containsKey(relative.replace('\\','/')))throw new IOException("directory_download_metadata_not_supported");Files.createDirectory(dst);}
                    else if (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) copyVerified(p,dst);
                    else throw new IOException("unsupported_source");
                }
            } else {
                if (entries.length != 1 || !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) throw new IOException("bad_snapshot");
                copyVerified(source, staging);
            }
            // A file may have been removed through Explorer while its encrypted
            // marker record remains. Retain that stale record until the new
            // non-replacing file commit succeeds, then retire it.
            if(Files.exists(metadata)) {
                metadataBackup=metadata.resolveSibling(".winup-import-zone-backup-"+UUID.randomUUID());
                Files.move(metadata,metadataBackup);
            }
            if(!snapshot.zoneIdentifiers.isEmpty()) {
                Files.createDirectories(metadata.getParent());
                metadataStage=metadata.resolveSibling(".winup-import-zone-"+UUID.randomUUID());
                byte[] bytes=JSON.writeValueAsBytes(snapshot);
                try {
                    try(FileChannel channel=FileChannel.open(metadataStage,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){ByteBuffer data=ByteBuffer.wrap(bytes);while(data.hasRemaining())channel.write(data);channel.force(true);}
                    if(!MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(bytes),hash(metadataStage)))throw new IOException("download_metadata_verification_failed");
                }finally{Arrays.fill(bytes,(byte)0);}
                Files.move(metadataStage,metadata);metadataCommitted=true;
            }
            // ATOMIC_MOVE on the Windows provider implicitly replaces an existing
            // target. The ordinary same-directory move uses a non-replacing rename.
            Files.move(staging, destination);
            dataCommitted=true;
            // Persist encrypted data and metadata before allowing the parent to remove originals.
            try(var files=Files.walk(storage)) {
                for(Path file : files.filter(p -> !p.equals(pathGuard) && Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)).toList()) {
                    try(FileChannel channel=FileChannel.open(file,StandardOpenOption.WRITE)) { channel.force(true); }
                }
            }
            committed = true;
        } finally {
            if(metadataStage!=null)Files.deleteIfExists(metadataStage);
            if (!committed)removeStage(staging);
            if(!dataCommitted) {
                if(metadataCommitted)Files.deleteIfExists(metadata);
                if(metadataBackup!=null)Files.move(metadataBackup,metadata);
            }else if(metadataBackup!=null)Files.deleteIfExists(metadataBackup);
        }
    }
    private static Object command(String[] p) throws Exception {
        String op = p[0];
        if (op.equals("open") || op.equals("create")) {
            if (p.length != 4) throw new IOException("bad_open_command");
            open(decode(p[1]), p[2], decode(p[3]), op.equals("create")); return Map.of("ok",true);
        }
        if (fs == null) throw new IOException("locked");
        return switch (op) {
            case "list" -> {
                var result = new ArrayList<Object>();
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(inside(decode(p[1])))) {
                    for (Path entry : stream) {
                        if (entry.getFileName().toString().startsWith(".winup-import-")) continue;
                        result.add(Map.of("name",entry.getFileName().toString(),"directory",Files.isDirectory(entry),
                            "size",Files.isDirectory(entry) ? 0L : Files.size(entry)));
                        if (result.size() > 10000) throw new IOException("too_many_files");
                    }
                }
                yield Map.of("ok",true,"items",result);
            }
            case "mkdir" -> { Files.createDirectory(inside(decode(p[1]))); yield Map.of("ok",true); }
            case "import" -> { importPath(Path.of(decode(p[1])), inside(decode(p[2])), decode(p[3])); yield Map.of("ok",true); }
            case "export" -> {
                Path destination = Path.of(decode(p[2]));
                if (Files.exists(destination)) throw new FileAlreadyExistsException("destination_exists");
                Path staging = Path.of(decode(p[3]));
                if (!staging.getParent().equals(destination.getParent()) || !staging.getFileName().toString().startsWith(".winup-export-")) throw new IOException("unsafe_export_stage");
                try { Path file=inside(decode(p[1]));copyVerified(file, staging);restoreZone(file,staging);Files.move(staging,destination); }
                finally { Files.deleteIfExists(staging); }
                yield Map.of("ok",true);
            }
            case "mount" -> {
                if (mount != null) throw new IOException("already_mounted");
                MountService service = IntegrationsLoader.loadAll(MountService.class)
                    .filter(x -> x.getClass().getName().equals("org.cryptomator.frontend.fuse.mount.WinFspMountProvider"))
                    .findFirst().orElseThrow(() -> new IOException("winfsp_missing"));
                mount = service.forFileSystem(fs.getPath("/")).setMountpoint(Path.of(decode(p[1])))
                    .setFileSystemName("WinUp").setVolumeName("WinUp")
                    .setMountFlags(service.getDefaultMountFlags()).mount();
                yield Map.of("ok",true);
            }
            case "close" -> { if (mount != null) { mount.close(); mount = null; } fs.close(); fs = null; yield Map.of("ok",true); }
            default -> throw new IOException("bad_command");
        };
    }
    public static void main(String[] args) throws Exception {
        // Libraries may print diagnostics while mounting/unmounting. Keep protocol replies distinct.
        System.setOut(System.err);
        try (BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = input.readLine()) != null) {
                if (line.length() > 8 * 1024 * 1024) break;
                try { reply(command(line.split("\t",-1))); }
                catch (Exception e) { reply(Map.of("ok",false,"error",e.getClass().getSimpleName(),"detail",String.valueOf(e.getMessage()))); }
            }
        } finally {
            if (mount != null) try { mount.close(); } catch(Exception ignored) {}
            if (fs != null) fs.close();
        }
    }
}

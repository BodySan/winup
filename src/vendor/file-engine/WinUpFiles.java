// WinUp adapter. Cryptomator cryptofs/cryptolib are used unchanged.
// AGPL-3.0-or-later. Commands/passwords travel only over inherited stdin.
import java.io.*;
import java.net.URI;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.channels.*;
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
    private static void importPath(Path source, Path destination, String manifest) throws Exception {
        // The parent WinUp process holds non-write/non-delete handles to every source.
        // Only it can delete originals, and only after this verified commit succeeds.
        // Iterate its immutable snapshot: a new child may be added to a directory
        // while the existing entries are held, but that child has no held handle.
        String[] entries = JSON.readValue(manifest, String[].class);
        if (entries.length == 0 || entries.length > 10000 || !entries[0].isEmpty()) throw new IOException("bad_snapshot");
        source = source.toAbsolutePath().normalize();
        if (Files.exists(destination)) throw new FileAlreadyExistsException("destination_exists");
        Path staging = destination.resolveSibling(".winup-import-" + UUID.randomUUID());
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
                    if (p.equals(source)) continue;
                    Path dst = staging.resolve(source.relativize(p).toString().replace('\\','/'));
                    if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(dst);
                    else if (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) copyVerified(p,dst);
                    else throw new IOException("unsupported_source");
                }
            } else {
                if (entries.length != 1 || !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) throw new IOException("bad_snapshot");
                copyVerified(source, staging);
            }
            // ATOMIC_MOVE on the Windows provider implicitly replaces an existing
            // target. The ordinary same-directory move uses a non-replacing rename.
            Files.move(staging, destination);
            // Persist encrypted data and metadata before allowing the parent to remove originals.
            try(var files=Files.walk(storage)) {
                for(Path file : files.filter(p -> !p.equals(pathGuard) && Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)).toList()) {
                    try(FileChannel channel=FileChannel.open(file,StandardOpenOption.WRITE)) { channel.force(true); }
                }
            }
            committed = true;
        } finally { if (!committed) removeStage(staging); }
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
                try { copyVerified(inside(decode(p[1])), staging); Files.move(staging,destination); }
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
